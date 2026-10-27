import gc
import logging
import time
import uuid
import weakref
from collections.abc import AsyncGenerator
from typing import Any
from unittest.mock import AsyncMock, MagicMock, Mock

import pytest

from guard_core._security_config_batch import apply_config_batch
from guard_core.core.checks import _strike_forget
from guard_core.core.checks._strike_forget import (
    forget_category_strikes,
    register_strike_middleware,
)
from guard_core.core.checks.helpers import _increment_suspicious_counts
from guard_core.core.checks.implementations.suspicious_activity import (
    SuspiciousActivityCheck,
)
from guard_core.core.initialization.handler_initializer import HandlerInitializer
from guard_core.detection_result import DetectionResult
from guard_core.handlers import ratelimit_handler
from guard_core.handlers.ipban_handler import IPBanManager
from guard_core.handlers.ratelimit_handler import (
    RateLimitManager,
    check_rate_limit_by_ip,
    rate_limit_handler,
    record_shared_violation,
)
from guard_core.handlers.redis_handler import RedisManager
from guard_core.models import SecurityConfig
from tests.conftest import REDIS_URL, MockGuardRequest, MockGuardResponse
from tests.engine_redis_commands import (
    engine_commands_sent,
    engine_redis_url,
    unwatch_engine_commands,
)

IP = "198.51.100.91"
OTHER = "198.51.100.92"
DETECT = "guard_core.core.checks.implementations.suspicious_activity"
THRESHOLD = 5


@pytest.fixture(autouse=True)
def clean_rate_limit_process_state() -> None:
    from guard_core.core.checks._strike_forget import forget_category_strikes

    ratelimit_handler.clear_by_ip_strikes()
    ratelimit_handler.clear_by_ip_request_windows()
    forget_category_strikes("rate_limit")


def _config(**overrides: Any) -> SecurityConfig:
    values: dict[str, Any] = {
        "enable_redis": True,
        "redis_url": engine_redis_url(REDIS_URL),
        "redis_prefix": f"test:wp3fu:clear:{uuid.uuid4().hex}:",
        "enable_penetration_detection": True,
        "enable_ip_banning": True,
        "auto_ban_threshold": THRESHOLD,
        "auto_ban_duration": 300,
        "enable_rate_limiting": True,
        "rate_limit": 1,
        "rate_limit_window": 60,
        "enable_rate_limit_auto_ban": True,
    }
    values.update(overrides)
    return SecurityConfig(**values)


class _Worker:
    def __init__(self, config: SecurityConfig, redis: RedisManager) -> None:
        self.bans: list[str] = []
        middleware = MagicMock()
        middleware.config = config
        middleware.logger = logging.getLogger("test_strike_clearing")
        middleware.suspicious_request_counts = {}
        middleware.rate_limit_handler.redis_handler = redis
        middleware.event_bus.send_middleware_event = AsyncMock()
        middleware.create_error_response = AsyncMock(
            return_value=MagicMock(status_code=400)
        )
        middleware.route_resolver.should_bypass_check = lambda *_: False
        self.middleware = middleware
        self.check = SuspiciousActivityCheck(middleware)

        async def record_ban(
            ip: str, duration: int, reason: str = "", *, grouped: bool = False
        ) -> int | None:
            self.bans.append(ip)
            return True

        self.check.ip_ban_manager = Mock(ban_ip=record_ban)

    async def strike(self, monkeypatch: pytest.MonkeyPatch, ip: str = IP) -> None:
        result = DetectionResult(
            is_threat=True,
            trigger_info="probe",
            threat_categories=["xss"],
            threat_scores={"xss": 1.0},
        )

        async def fake(*_args: Any, **_kwargs: Any) -> DetectionResult:
            return result

        monkeypatch.setattr(f"{DETECT}.get_cached_detection_result", fake)
        request = MagicMock()
        request.state.is_whitelisted = False
        request.state.client_ip = ip
        request.state.route_config = None
        request.url_full = "https://test/x"
        await self.check.check(request)


@pytest.fixture
async def redis() -> AsyncGenerator[RedisManager, None]:
    config = _config()
    manager = RedisManager(config)
    await manager.initialize()
    ratelimit_handler.clear_by_ip_strikes()
    try:
        yield manager
    finally:
        await manager.delete_pattern("*")
        await manager.close()
        unwatch_engine_commands(config.redis_url)
        ratelimit_handler.clear_by_ip_strikes()


@pytest.fixture
def ban_manager(redis: RedisManager) -> IPBanManager:
    manager = IPBanManager()
    manager.redis_handler = redis
    return manager


async def _keys(redis: RedisManager, pattern: str) -> list[str]:
    async with redis.get_connection() as conn:
        return sorted(await conn.keys(f"{redis.config.redis_prefix}{pattern}"))


async def test_a_detection_strike_does_not_survive_a_manual_unban(
    redis: RedisManager, ban_manager: IPBanManager, monkeypatch: pytest.MonkeyPatch
) -> None:
    first, second = _Worker(redis.config, redis), _Worker(redis.config, redis)
    for index in range(THRESHOLD - 1):
        await (first, second)[index % 2].strike(monkeypatch)
    await ban_manager.ban_ip(IP, 600, "manual")

    await ban_manager.unban_ip(IP)
    await second.strike(monkeypatch)

    assert first.bans == second.bans == []


async def test_a_rate_limit_strike_does_not_survive_a_manual_unban(
    redis: RedisManager, ban_manager: IPBanManager
) -> None:
    config = redis.config
    for _ in range(THRESHOLD):
        await check_rate_limit_by_ip(IP, config, redis)
    assert await _keys(redis, f"rate_limit:violations:{IP}")
    await ban_manager.unban_ip(IP)

    assert await _keys(redis, f"rate_limit:violations:{IP}") == []
    assert IP not in ratelimit_handler._by_ip_autoban_counts.for_app(config)


async def test_unban_ip_clears_the_strikes_in_every_middleware(
    redis: RedisManager, ban_manager: IPBanManager, monkeypatch: pytest.MonkeyPatch
) -> None:
    first, second = _Worker(redis.config, redis), _Worker(redis.config, redis)
    await first.strike(monkeypatch)
    await second.strike(monkeypatch)
    await second.strike(monkeypatch, OTHER)

    await ban_manager.unban_ip(IP)

    assert IP not in first.middleware.suspicious_request_counts
    assert IP not in second.middleware.suspicious_request_counts
    assert OTHER in second.middleware.suspicious_request_counts
    assert await _keys(redis, f"detection:strikes:{IP}*") == []
    assert await _keys(redis, f"detection:strikes:{OTHER}*")


async def test_the_ban_reset_clears_every_strike_of_both_families(
    redis: RedisManager, ban_manager: IPBanManager, monkeypatch: pytest.MonkeyPatch
) -> None:
    first, second = _Worker(redis.config, redis), _Worker(redis.config, redis)
    await first.strike(monkeypatch)
    await second.strike(monkeypatch, OTHER)
    for _ in range(3):
        await check_rate_limit_by_ip(IP, redis.config, redis)

    await ban_manager.reset()

    assert first.middleware.suspicious_request_counts == {}
    assert second.middleware.suspicious_request_counts == {}
    assert ratelimit_handler._by_ip_autoban_counts.for_app(redis.config) == {}
    assert await _keys(redis, "detection:*") == []
    assert await _keys(redis, "rate_limit:violations:*") == []


async def test_unban_inside_clears_only_the_strikes_of_the_removed_members(
    redis: RedisManager, ban_manager: IPBanManager, monkeypatch: pytest.MonkeyPatch
) -> None:
    worker = _Worker(redis.config, redis)
    inside, outside = "198.51.100.10", "203.0.113.10"
    await worker.strike(monkeypatch, inside)
    await worker.strike(monkeypatch, outside)
    await ban_manager.ban_ip(inside, 600, "manual")

    await ban_manager.unban_inside(["198.51.100.0/24"])

    assert inside not in worker.middleware.suspicious_request_counts
    assert outside in worker.middleware.suspicious_request_counts
    assert await _keys(redis, f"detection:strikes:{outside}")


async def test_the_rate_limit_reset_keeps_the_detection_strikes(
    redis: RedisManager, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = redis.config
    app = RateLimitManager(config)
    HandlerInitializer(config, rate_limit_handler=app)
    await app.initialize_redis(redis)
    worker = _Worker(config, redis)
    await worker.strike(monkeypatch)
    _increment_suspicious_counts(worker.middleware, IP, "rate_limit")
    for _ in range(3):
        await check_rate_limit_by_ip(IP, config, redis)

    await rate_limit_handler(config).reset()

    assert dict(worker.middleware.suspicious_request_counts[IP]) == {"xss": 1}
    assert ratelimit_handler._by_ip_autoban_counts.for_app(config) == {}
    assert await _keys(redis, "rate_limit:violations:*") == []
    assert await _keys(redis, f"detection:strikes:{IP}")


async def test_clearing_the_windows_leaves_the_violations_alone(
    redis: RedisManager,
) -> None:
    await record_shared_violation(redis, IP)
    async with redis.get_connection() as conn:
        await conn.set(f"{redis.config.redis_prefix}rate_limit:rate:{IP}", "1")

    assert await redis.delete_pattern("rate_limit:rate:*") == 1

    assert await _keys(redis, "rate_limit:rate:*") == []
    assert await _keys(redis, "rate_limit:violations:*")


async def _command_calls(redis: RedisManager, command: str) -> int:
    return await engine_commands_sent(redis.config.redis_url, command)


async def _seed_prefixed_keys(redis: RedisManager) -> None:
    async with redis.get_connection() as conn:
        for name in ("banned_ips:1.1.1.1", "rate_limit:rate:1.1.1.1", "x:1"):
            await conn.set(f"{redis.config.redis_prefix}{name}", "1")


async def test_every_prefix_wide_clear_scans_and_unlinks_and_never_runs_keys(
    redis: RedisManager,
    ban_manager: IPBanManager,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = redis.config
    app = RateLimitManager(config)
    HandlerInitializer(config, rate_limit_handler=app)
    await app.initialize_redis(redis)
    await _seed_prefixed_keys(redis)
    worker = _Worker(config, redis)
    await worker.strike(monkeypatch)
    keys_before = await _command_calls(redis, "keys")
    scans_before = await _command_calls(redis, "scan")
    unlinks_before = await _command_calls(redis, "unlink")

    await rate_limit_handler(config).reset()
    await ban_manager.reset()
    await ban_manager.unban_inside(["1.1.1.0/24"])
    await redis.delete_pattern("x:*")
    assert await redis.keys("x:*") == []

    assert await _command_calls(redis, "keys") == keys_before
    assert await _command_calls(redis, "scan") > scans_before
    assert await _command_calls(redis, "unlink") > unlinks_before


async def test_the_keys_helper_returns_the_matching_keys_and_none_when_disabled(
    redis: RedisManager,
) -> None:
    await _seed_prefixed_keys(redis)

    found = await redis.keys("rate_limit:rate:*")

    assert found == [f"{redis.config.redis_prefix}rate_limit:rate:1.1.1.1"]
    assert await RedisManager(SecurityConfig(enable_redis=False)).keys("*") is None


async def test_the_scan_unlink_walks_more_than_one_batch_in_three_unlinks(
    redis: RedisManager,
) -> None:
    async with redis.get_connection() as conn:
        for number in range(1200):
            await conn.set(f"{redis.config.redis_prefix}bulk:{number}", "1")
    unlinks_before = await _command_calls(redis, "unlink")

    assert await redis.delete_pattern("bulk:*") == 1200

    assert await _keys(redis, "bulk:*") == []
    assert await _command_calls(redis, "unlink") - unlinks_before == 3


def _guarded(config: SecurityConfig) -> RateLimitManager:
    manager = RateLimitManager(config)
    HandlerInitializer(config, rate_limit_handler=manager)
    return manager


async def _statuses(manager: RateLimitManager, count: int) -> list[int]:
    async def error(status: int, message: str) -> MockGuardResponse:
        return MockGuardResponse(message, status)

    statuses = []
    for _ in range(count):
        request = MockGuardRequest(path="/x", client_host="203.0.113.9")
        response = await manager.check_rate_limit(request, "203.0.113.9", error)
        statuses.append(200 if response is None else response.status_code)
    return statuses


async def test_an_equal_config_resets_every_equal_guarded_app(
    caplog: pytest.LogCaptureFixture,
) -> None:
    app_config = SecurityConfig(enable_redis=False, rate_limit=2, rate_limit_window=60)
    app = _guarded(app_config)
    assert await _statuses(app, 3) == [200, 200, 429]
    rebuilt = SecurityConfig(enable_redis=False, rate_limit=2, rate_limit_window=60)

    with caplog.at_level(logging.WARNING, logger="guard_core.handlers.ratelimit"):
        await rate_limit_handler(rebuilt).reset()

    assert await _statuses(app, 1) == [200]
    messages = [r.getMessage() for r in caplog.records]
    assert any("resetting the 1 guarded app(s)" in m for m in messages)


async def test_equality_survives_a_dynamic_rule_update_and_callables() -> None:
    def modifier(response: Any) -> Any:
        return response

    app_config = SecurityConfig(
        enable_redis=False,
        rate_limit=2,
        rate_limit_window=60,
        custom_response_modifier=modifier,
    )
    app = _guarded(app_config)
    apply_config_batch(app_config, {"rate_limit": 2})
    assert await _statuses(app, 3) == [200, 200, 429]
    rebuilt = SecurityConfig(
        enable_redis=False,
        rate_limit=2,
        rate_limit_window=60,
        custom_response_modifier=modifier,
    )

    await rate_limit_handler(rebuilt).reset()

    assert await _statuses(app, 1) == [200]


async def test_an_unequal_config_without_redis_resets_nothing_and_says_so(
    caplog: pytest.LogCaptureFixture,
) -> None:
    app = _guarded(
        SecurityConfig(enable_redis=False, rate_limit=2, rate_limit_window=60)
    )
    assert await _statuses(app, 3) == [200, 200, 429]
    other = SecurityConfig(enable_redis=False, rate_limit=7, rate_limit_window=60)

    with caplog.at_level(logging.WARNING, logger="guard_core.handlers.ratelimit"):
        await rate_limit_handler(other).reset()

    assert await _statuses(app, 1) == [429]
    assert any("reset() cleared nothing" in r.getMessage() for r in caplog.records)


async def test_an_unequal_config_with_redis_clears_the_windows_through_a_new_client(
    redis: RedisManager,
) -> None:
    config = redis.config
    async with redis.get_connection() as conn:
        await conn.set(f"{config.redis_prefix}rate_limit:rate:{IP}", "1")
        await conn.set(f"{config.redis_prefix}other:{IP}", "1")
    admin = _config(redis_prefix=config.redis_prefix, rate_limit=9)

    await rate_limit_handler(admin).reset()

    assert await _keys(redis, "rate_limit:rate:*") == []
    assert await _keys(redis, "other:*")


async def test_a_config_that_cannot_be_compared_is_not_equal() -> None:
    class Unequal(SecurityConfig):
        def __eq__(self, other: object) -> bool:
            raise RuntimeError("no comparison")

    assert ratelimit_handler._configs_equal(Unequal(), SecurityConfig()) is False


def test_the_registry_forgets_a_middleware_when_it_goes() -> None:
    class Holder:
        config = SecurityConfig(enable_redis=False)
        suspicious_request_counts: dict[str, dict[str, int]] = {}

    holder = Holder()
    register_strike_middleware(holder)
    registered = holder in _strike_forget._registered_middlewares()
    alive = weakref.ref(holder)

    del holder
    gc.collect()

    assert registered
    assert alive() is None


def test_a_middleware_that_cannot_be_weakly_referenced_warns_once(
    caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    class Slotted:
        __slots__ = ("config", "suspicious_request_counts")
        config: SecurityConfig
        suspicious_request_counts: dict[str, dict[str, int]]

    monkeypatch.setattr(_strike_forget, "_unregistrable_warned", False)

    with caplog.at_level(logging.WARNING):
        register_strike_middleware(Slotted())
        register_strike_middleware(Slotted())

    assert (
        len([r for r in caplog.records if "weakly referenced" in r.getMessage()]) == 1
    )


def test_forgetting_a_category_drops_plain_dict_counts_too() -> None:
    class Holder:
        def __init__(self) -> None:
            self.config = SecurityConfig(enable_redis=False)
            self.suspicious_request_counts: dict[str, dict[str, int]] = {
                IP: {"rate_limit": 2, "xss": 1},
                OTHER: {"rate_limit": 1},
            }

    holder = Holder()
    register_strike_middleware(holder)

    forget_category_strikes("rate_limit")

    assert holder.suspicious_request_counts == {IP: {"xss": 1}}


def test_a_strike_registers_its_middleware() -> None:
    middleware = MagicMock()
    middleware.config = SecurityConfig(enable_redis=False)
    middleware.suspicious_request_counts = {}

    _increment_suspicious_counts(middleware, IP, "xss")

    assert middleware in _strike_forget._registered_middlewares()


async def test_a_failed_redis_clear_on_unban_is_logged_and_the_unban_stands(
    caplog: pytest.LogCaptureFixture,
) -> None:
    manager = IPBanManager()
    manager.banned_ips[IP] = time.time() + 60
    redis = Mock(
        write_atomically=AsyncMock(),
        delete=AsyncMock(side_effect=RuntimeError("redis down")),
        forget_detection_strikes=AsyncMock(),
    )
    manager.redis_handler = redis

    with caplog.at_level(logging.WARNING):
        await manager.unban_ip(IP)

    assert IP not in manager.banned_ips
    assert any("could not be cleared" in r.getMessage() for r in caplog.records)


async def test_a_failed_redis_clear_on_the_ban_reset_is_logged(
    caplog: pytest.LogCaptureFixture,
) -> None:
    manager = IPBanManager()
    manager.redis_handler = Mock(
        config=SecurityConfig(enable_redis=False),
        get_connection=Mock(side_effect=RuntimeError("redis down")),
    )

    with caplog.at_level(logging.WARNING):
        await manager._forget_all_strikes()

    assert any("could not be cleared" in r.getMessage() for r in caplog.records)


def test_the_warning_flag_for_an_unregistrable_middleware_starts_unset() -> None:
    assert _strike_forget._unregistrable_warned is False


def test_the_unregistrable_warning_has_the_exact_text(
    caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    class Slotted:
        __slots__ = ("config", "suspicious_request_counts")
        config: SecurityConfig
        suspicious_request_counts: dict[str, dict[str, int]]

    monkeypatch.setattr(_strike_forget, "_unregistrable_warned", False)

    with caplog.at_level(logging.WARNING):
        register_strike_middleware(Slotted())

    assert [(r.name, r.getMessage()) for r in caplog.records] == [
        (
            "guard_core.core.checks.strike_forget",
            "This middleware cannot be weakly referenced, so unban and reset calls "
            "cannot clear its in-process strike counts. This is logged once.",
        )
    ]


def test_a_forgotten_category_does_not_come_back_with_the_next_strike() -> None:
    middleware = MagicMock()
    middleware.config = SecurityConfig(enable_redis=False)
    middleware.suspicious_request_counts = {}
    _increment_suspicious_counts(middleware, IP, "rate_limit")
    _increment_suspicious_counts(middleware, IP, "xss")

    forget_category_strikes("rate_limit")
    _increment_suspicious_counts(middleware, IP, "xss")

    assert dict(middleware.suspicious_request_counts[IP]) == {"xss": 2}
