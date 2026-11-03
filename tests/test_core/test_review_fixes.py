import logging
from collections.abc import AsyncGenerator, AsyncIterator
from contextlib import asynccontextmanager
from typing import Any
from unittest.mock import AsyncMock, MagicMock, Mock

import pytest

from guard_core.core.checks.implementations.rate_limit import RateLimitCheck
from guard_core.core.checks.implementations.suspicious_activity import (
    SuspiciousActivityCheck,
)
from guard_core.detection_result import DetectionResult
from guard_core.handlers import ratelimit_handler
from guard_core.handlers.dynamic_rule_handler import DynamicRuleManager
from guard_core.handlers.ipban_handler import IPBanManager
from guard_core.handlers.ratelimit_handler import RateLimitManager, rate_limit_handler
from guard_core.handlers.redis_handler import RedisManager
from guard_core.models import SecurityConfig
from guard_core.protocols.redis_protocol import RedisHandlerProtocol
from tests.conftest import (
    REDIS_URL,
    MockGuardRequest,
    MockGuardResponse,
    suite_redis_prefix,
)

DETECT = "guard_core.core.checks.implementations.suspicious_activity"


@pytest.fixture(autouse=True)
def clean_rate_limit_process_state() -> None:
    from guard_core.core.checks._strike_forget import forget_category_strikes

    ratelimit_handler.clear_by_ip_strikes()
    ratelimit_handler.clear_by_ip_request_windows()
    forget_category_strikes("rate_limit")


INSIDE = "198.51.100.10"
OUTSIDE = "203.0.113.10"


def _config(**overrides: object) -> SecurityConfig:
    values: dict[str, Any] = {
        "enable_redis": True,
        "redis_url": REDIS_URL,
        "redis_prefix": suite_redis_prefix("wp3fu:review"),
        "enable_penetration_detection": True,
        "enable_ip_banning": True,
        "auto_ban_threshold": 100,
        "auto_ban_duration": 300,
        "enable_rate_limiting": True,
        "rate_limit": 1,
        "rate_limit_window": 60,
        "enable_rate_limit_auto_ban": True,
    }
    values.update(overrides)
    return SecurityConfig(**values)


@pytest.fixture
async def redis() -> AsyncGenerator[RedisManager, None]:
    manager = RedisManager(_config())
    await manager.initialize()
    ratelimit_handler.clear_by_ip_strikes()
    try:
        yield manager
    finally:
        await manager.delete_pattern("*")
        await manager.close()
        ratelimit_handler.clear_by_ip_strikes()


def _middleware(config: SecurityConfig, redis: RedisHandlerProtocol) -> MagicMock:
    middleware = MagicMock()
    middleware.config = config
    middleware.logger = logging.getLogger("test_review_fixes")
    middleware.suspicious_request_counts = {}
    middleware.rate_limit_handler = rate_limit_handler(config)
    middleware.rate_limit_handler.redis_handler = redis
    middleware.event_bus.send_middleware_event = AsyncMock()
    middleware.create_error_response = AsyncMock(
        side_effect=lambda status_code, default_message: MockGuardResponse(
            default_message, status_code
        )
    )
    middleware.route_resolver.should_bypass_check = lambda *_: False
    return middleware


async def _detect(
    check: SuspiciousActivityCheck, monkeypatch: pytest.MonkeyPatch, ip: str
) -> None:
    result = DetectionResult(
        is_threat=True,
        trigger_info="probe",
        threat_categories=["xss"],
        threat_scores={"xss": 1.0},
    )

    async def fake(*_args: object, **_kwargs: object) -> DetectionResult:
        return result

    monkeypatch.setattr(f"{DETECT}.get_cached_detection_result", fake)
    request = MagicMock()
    request.state.is_whitelisted = False
    request.state.client_ip = ip
    request.state.route_config = None
    request.url_full = "https://test/x"
    await check.check(request)


async def _keys(redis: RedisManager, pattern: str) -> list[str]:
    async with redis.get_connection() as conn:
        return sorted(await conn.keys(f"{redis.config.redis_prefix}{pattern}"))


async def _seed(
    redis: RedisManager, monkeypatch: pytest.MonkeyPatch
) -> tuple[MagicMock, IPBanManager, DynamicRuleManager]:
    middleware = _middleware(redis.config, redis)
    check = SuspiciousActivityCheck(middleware)
    check.ip_ban_manager = Mock(_ban_ip_escalating=AsyncMock(return_value=True))
    for ip in (INSIDE, OUTSIDE):
        await _detect(check, monkeypatch, ip)
        await ratelimit_handler.check_rate_limit_by_ip(ip, redis.config, redis)
        await ratelimit_handler.check_rate_limit_by_ip(ip, redis.config, redis)
    ban_manager = IPBanManager()
    ban_manager.redis_handler = redis
    return middleware, ban_manager, DynamicRuleManager(redis.config)


async def _assert_only_outside_keeps_strikes(
    redis: RedisManager, middleware: MagicMock
) -> None:
    assert INSIDE not in middleware.suspicious_request_counts
    assert OUTSIDE in middleware.suspicious_request_counts
    assert INSIDE not in ratelimit_handler._by_ip_autoban_counts.for_app(redis.config)
    assert OUTSIDE in ratelimit_handler._by_ip_autoban_counts.for_app(redis.config)
    assert await _keys(redis, f"detection:strikes*{INSIDE}*") == []
    assert await _keys(redis, f"rate_limit:violations:{INSIDE}") == []
    assert await _keys(redis, f"detection:strikes:{OUTSIDE}")
    assert await _keys(redis, f"rate_limit:violations:{OUTSIDE}")


@pytest.mark.parametrize("entry", ["198.51.100.0/24", "198.51.100.10/32", INSIDE])
async def test_a_whitelisted_entry_resets_the_strikes_of_what_it_covers(
    redis: RedisManager, monkeypatch: pytest.MonkeyPatch, entry: str
) -> None:
    middleware, _, rules = await _seed(redis, monkeypatch)

    await rules._apply_ip_whitelist([entry])

    await _assert_only_outside_keeps_strikes(redis, middleware)


async def test_a_range_covering_two_addresses_resets_both_but_not_a_neighbour(
    redis: RedisManager, monkeypatch: pytest.MonkeyPatch
) -> None:
    middleware, _, rules = await _seed(redis, monkeypatch)
    check = SuspiciousActivityCheck(middleware)
    check.ip_ban_manager = Mock(_ban_ip_escalating=AsyncMock(return_value=True))
    await _detect(check, monkeypatch, "198.51.101.1")

    await rules._apply_ip_whitelist(["198.51.100.0/24"])

    assert "198.51.101.1" in middleware.suspicious_request_counts
    assert await _keys(redis, "detection:strikes:198.51.101.1|*")


async def test_the_range_reset_reads_an_ipv6_address_by_stripping_the_prefix(
    redis: RedisManager, monkeypatch: pytest.MonkeyPatch
) -> None:
    middleware = _middleware(redis.config, redis)
    check = SuspiciousActivityCheck(middleware)
    check.ip_ban_manager = Mock(_ban_ip_escalating=AsyncMock(return_value=True))
    for ip in ("2001:db8::1", "2001:db9::1"):
        await _detect(check, monkeypatch, ip)

    IPBanManager().redis_handler = redis

    await DynamicRuleManager(redis.config)._apply_ip_whitelist(["2001:db8::/32"])

    assert "2001:db8::/64" not in middleware.suspicious_request_counts
    assert "2001:db9::/64" in middleware.suspicious_request_counts
    assert await _keys(redis, "detection:strikes:2001:db8::/64*") == []
    assert await _keys(redis, "detection:strikes:2001:db9::/64|*")


async def test_an_empty_range_list_clears_nothing(redis: RedisManager) -> None:
    manager = IPBanManager()
    manager.redis_handler = redis

    await manager.forget_strikes_inside([])


async def test_a_failed_redis_range_clear_is_logged(
    caplog: pytest.LogCaptureFixture,
) -> None:
    manager = IPBanManager()
    manager.redis_handler = Mock(
        config=SecurityConfig(enable_redis=False),
        get_connection=Mock(side_effect=RuntimeError("redis down")),
    )

    with caplog.at_level(logging.WARNING):
        await manager.forget_strikes_inside(["198.51.100.0/24"])

    assert any("inside a range" in r.getMessage() for r in caplog.records)


async def test_the_rate_limit_feed_never_records_detection_strikes(
    redis: RedisManager, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = redis.config
    config.auto_ban_threshold = 2
    middleware = _middleware(config, redis)
    bans: list[str] = []

    async def ban_ip(
        ip: str, duration: int, reason: str = "", *, grouped: bool = False
    ) -> int | None:
        bans.append(ip)
        return duration

    check = RateLimitCheck(middleware)
    check.ip_ban_manager = Mock(_ban_ip_escalating=ban_ip)
    calls = {"count": 0}
    real = ratelimit_handler.record_shared_violation

    async def flaky(handler: RedisHandlerProtocol, ip: str) -> int:
        calls["count"] += 1
        if calls["count"] == 2:
            raise RuntimeError("redis hiccup")
        return await real(handler, ip)

    monkeypatch.setattr(
        "guard_core.core.checks.implementations.rate_limit.record_shared_violation",
        flaky,
    )
    for _ in range(2):
        request = MockGuardRequest(path="/x", client_host="203.0.113.77")
        request.state.client_ip = "203.0.113.77"
        request.state.route_config = None
        request.state.is_whitelisted = False
        await check._record_rate_limit_autoban(request, "203.0.113.77", "trigger")

    assert await _keys(redis, "detection:*") == []
    assert bans == ["203.0.113.77"]


async def test_keys_returns_a_key_once_when_scan_yields_it_twice(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager = RedisManager(SecurityConfig(enable_redis=True))

    async def scan_iter(*_args: object, **_kwargs: object) -> object:
        for key in ("p:a", "p:b", "p:a", "p:c", "p:b"):
            yield str(key)

    conn = Mock(scan_iter=scan_iter)

    @asynccontextmanager
    async def get_connection() -> AsyncIterator[Any]:
        yield conn

    monkeypatch.setattr(manager, "get_connection", get_connection)
    assert await manager.keys("*") == ["p:a", "p:b", "p:c"]


def _app(config: SecurityConfig) -> RateLimitManager:
    from guard_core.core.initialization.handler_initializer import HandlerInitializer

    manager = RateLimitManager(config)
    HandlerInitializer(config, rate_limit_handler=manager)
    return manager


async def test_the_unbound_reset_warning_says_no_request_windows_were_cleared(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SecurityConfig(enable_redis=False, rate_limit=7)

    with caplog.at_level(logging.INFO, logger="guard_core.handlers.ratelimit"):
        await rate_limit_handler(config).reset()

    assert [(r.levelno, r.getMessage()) for r in caplog.records] == [
        (
            logging.WARNING,
            "this config object is not the one any guarded app was built with; "
            "reset() cleared nothing",
        ),
        (
            logging.INFO,
            "reset() also cleared the rate-limit auto-ban strikes (process memory); "
            "detection strikes and active bans are kept",
        ),
    ]


async def test_the_app_reset_names_redis_only_when_it_was_cleared(
    caplog: pytest.LogCaptureFixture, redis: RedisManager
) -> None:
    plain = SecurityConfig(enable_redis=False, rate_limit=2)
    app = _app(plain)
    with caplog.at_level(logging.INFO, logger="guard_core.handlers.ratelimit"):
        await rate_limit_handler(plain).reset()
    assert [r.getMessage() for r in caplog.records] == [
        "reset() also cleared the rate-limit auto-ban strikes (process memory); "
        "detection strikes and active bans are kept"
    ]
    assert app.bound_to_app
    caplog.clear()

    config = redis.config
    shared = _app(config)
    await shared.initialize_redis(redis)
    with caplog.at_level(logging.INFO, logger="guard_core.handlers.ratelimit"):
        await rate_limit_handler(config).reset()
    assert [r.getMessage() for r in caplog.records] == [
        "reset() also cleared the rate-limit auto-ban strikes (process memory and "
        "Redis); detection strikes and active bans are kept"
    ]


async def test_a_failed_redis_clear_is_not_reported_as_cleared(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SecurityConfig(enable_redis=True, redis_url="redis://x:1")
    app = _app(config)
    app.redis_handler = Mock(delete_pattern=AsyncMock(side_effect=RuntimeError("down")))

    with caplog.at_level(logging.INFO, logger="guard_core.handlers.ratelimit"):
        await rate_limit_handler(config).reset()

    messages = [r.getMessage() for r in caplog.records]
    assert "Failed to reset Redis rate limits: down" in messages
    assert (
        "reset() also cleared the rate-limit auto-ban strikes (process memory); "
        "detection strikes and active bans are kept"
    ) in messages
