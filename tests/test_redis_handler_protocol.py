import types
from collections.abc import AsyncGenerator
from typing import Any, Protocol, runtime_checkable
from unittest.mock import MagicMock

import pytest
from typing_extensions import get_protocol_members

from guard_core.core.checks._shared_strikes import (
    forget_shared_detection_strikes,
    read_shared_detection_categories,
    record_shared_detection_strikes,
)
from guard_core.core.checks.factory import (
    _collect_route_configs,
    _route_config_revision,
)
from guard_core.core.initialization.handler_initializer import HandlerInitializer
from guard_core.handlers._dynamic_rule_application import RuleSideEffects
from guard_core.handlers.behavior_handler import BehaviorRule, BehaviorTracker
from guard_core.handlers.cloud_ip_stores import RedisCloudIpStore
from guard_core.handlers.dynamic_rule_handler import DynamicRuleManager
from guard_core.handlers.ipban_handler import IPBanManager, ip_ban_manager
from guard_core.handlers.ratelimit_handler import RateLimitManager
from guard_core.handlers.security_headers_handler import SecurityHeadersManager
from guard_core.handlers.suspatterns_handler import SusPatternsManager
from guard_core.models import SecurityConfig
from guard_core.protocols.middleware_protocol import GuardMiddlewareProtocol
from guard_core.protocols.redis_protocol import RedisHandlerProtocol
from guard_core.protocols.response_protocol import GuardResponse
from tests.conftest import MockGuardRequest
from tests.protocol_only_redis import MEMBERS, protocol_only_handler

IP = "198.51.100.77"
NETWORK = "203.0.113.0/24"
DAY = 86400


@runtime_checkable
class RecordingRedisHandler(RedisHandlerProtocol, Protocol):
    used: set[str]


@pytest.fixture
async def handler() -> AsyncGenerator[RecordingRedisHandler, None]:
    async with protocol_only_handler() as fake:
        assert isinstance(fake, RecordingRedisHandler)
        yield fake


def _fresh_ban_manager(handler: RecordingRedisHandler) -> IPBanManager:
    ip_ban_manager.config = handler.config
    ip_ban_manager.redis_handler = handler
    ip_ban_manager.banned_ips.clear()
    ip_ban_manager.banned_networks.clear()
    return ip_ban_manager


def _request() -> MockGuardRequest:
    return MockGuardRequest(path="/x", client_host=IP)


async def _error(status: int, message: str) -> GuardResponse:
    return MagicMock(status_code=status)


def test_the_fake_has_only_the_declared_members(
    handler: RecordingRedisHandler,
) -> None:
    public = {name for name in vars(handler) if not name.startswith("_")}
    assert public - {"used"} == MEMBERS
    for undeclared in ("exists", "safe_operation", "close", "ban_floor_key"):
        assert not hasattr(handler, undeclared)


def test_the_protocol_declares_every_method_the_engine_calls() -> None:
    assert {
        "config",
        "get_many",
        "set_key_if_absent",
        "incr",
        "write_atomically",
        "write_ban_extending_only",
        "owned_ban_members",
        "owned_ban_state",
        "purge_owned_ban",
        "disown_ban",
        "record_sliding_window_hit",
        "count_sliding_window_hits",
        "sum_indexed_window_hits",
        "detection_correlation_keys",
        "record_detection_strikes",
        "read_detection_categories",
        "forget_detection_strikes",
        "delete_pattern",
        "initialize_agent",
    } <= MEMBERS


async def test_bans_run_on_a_protocol_only_handler(
    handler: RecordingRedisHandler,
) -> None:
    manager = _fresh_ban_manager(handler)
    assert await manager.ban_ip(IP, 300, "wp69")
    manager.banned_ips.clear()
    assert await manager.is_ip_banned(IP)
    await manager.unban_ip(IP)
    manager.banned_ips.clear()
    assert not await manager.is_ip_banned(IP)


async def test_rule_owned_bans_run_on_a_protocol_only_handler(
    handler: RecordingRedisHandler,
) -> None:
    manager = _fresh_ban_manager(handler)
    DynamicRuleManager._instance = None
    worker = DynamicRuleManager(handler.config)
    worker.redis_handler = handler
    effects = RuleSideEffects()
    for target in (IP, NETWORK):
        await worker._apply_ip_bans(
            [target], DAY, effects.created_bans, effects.skipped
        )
    assert await manager.owned_rule_ban_targets()
    assert await manager.rule_owns_live_ban(f"banned_ips:{IP}")
    assert await manager.revoke_rule_ban(IP) in (0, 1, 2, 3)
    await manager.disown_rule_ban(NETWORK)
    assert isinstance(await manager.purge_rule_owned_bans(), dict)
    assert {
        "write_ban_extending_only",
        "owned_ban_members",
        "owned_ban_state",
        "purge_owned_ban",
        "disown_ban",
    } <= handler.used


async def test_rate_limits_run_on_a_protocol_only_handler(
    handler: RecordingRedisHandler,
) -> None:
    limiter = RateLimitManager(handler.config)
    await limiter.initialize_redis(handler)
    first = await limiter.check_rate_limit(
        _request(), IP, _error, rate_limit=1, rate_limit_window=60
    )
    second = await limiter.check_rate_limit(
        _request(), IP, _error, rate_limit=1, rate_limit_window=60
    )
    assert first is None and second is not None
    from guard_core.handlers.ratelimit_handler import (
        forget_shared_violations,
        record_shared_violation,
    )

    assert await record_shared_violation(handler, IP) >= 1
    await forget_shared_violations(handler, IP)
    await limiter.reset()
    assert {"record_sliding_window_hit", "delete", "delete_pattern"} <= handler.used
    assert "get_connection" in handler.used


async def test_behavior_rules_run_on_a_protocol_only_handler(
    handler: RecordingRedisHandler,
) -> None:
    tracker = BehaviorTracker(handler.config)
    await tracker.initialize_redis(handler)
    rule = BehaviorRule("usage", threshold=2, window=60)
    for _ in range(3):
        await tracker.track_endpoint_usage("/probe", IP, rule)
    assert await tracker.track_endpoint_usage("/probe", IP, rule, record=False)
    assert await tracker.count_recent_rule_hits(IP, 60) >= 1
    assert {
        "record_sliding_window_hit",
        "count_sliding_window_hits",
        "sum_indexed_window_hits",
    } <= handler.used


async def test_detection_strikes_run_on_a_protocol_only_handler(
    handler: RecordingRedisHandler,
) -> None:
    middleware: Any = types.SimpleNamespace(
        config=handler.config,
        rate_limit_handler=types.SimpleNamespace(redis_handler=handler),
    )
    strikes = await record_shared_detection_strikes(
        middleware, IP, ["xss", "sqli"], 60, 100
    )
    assert strikes is not None and strikes.total == 1
    assert await read_shared_detection_categories(handler, IP, 60) == ["sqli", "xss"]
    await forget_shared_detection_strikes(middleware, IP)
    assert await read_shared_detection_categories(handler, IP, 60) == []
    assert handler.detection_correlation_keys(IP)
    assert {
        "record_detection_strikes",
        "read_detection_categories",
        "forget_detection_strikes",
        "detection_correlation_keys",
    } <= handler.used


async def test_cloud_ranges_headers_and_patterns_run_on_a_protocol_only_handler(
    handler: RecordingRedisHandler,
) -> None:
    store = RedisCloudIpStore(handler)
    await store.set("AWS", {"203.0.113.0/24|eu"}, ttl=60)
    assert await store.get("AWS") == {"203.0.113.0/24|eu"}
    await store.clear()
    assert await store.get("AWS") is None

    headers = SecurityHeadersManager()
    headers.configure(csp={"default-src": ["'self'"]})
    await headers.initialize_redis(handler, handler.config)
    await headers.reset()

    SusPatternsManager._instance = None
    patterns = SusPatternsManager()
    await patterns.initialize_redis(handler)
    assert await SusPatternsManager.add_pattern("wp69-pin", custom=True)
    assert await SusPatternsManager.remove_pattern("wp69-pin", custom=True)
    assert {"get_key", "set_key", "keys", "delete", "get_many", "write_atomically"} <= (
        handler.used
    )


async def test_the_initializer_runs_on_a_protocol_only_handler(
    handler: RecordingRedisHandler,
) -> None:
    IPBanManager._instance = None
    initializer = HandlerInitializer(handler.config, redis_handler=handler)
    await initializer.initialize_redis_handlers()
    await handler.initialize_agent(MagicMock())
    assert {"initialize", "initialize_agent", "set_key_if_absent"} <= handler.used


def test_the_middleware_protocol_declares_guard_decorator() -> None:
    assert "guard_decorator" in get_protocol_members(GuardMiddlewareProtocol)


def test_a_middleware_without_guard_decorator_still_works() -> None:
    bare: Any = types.SimpleNamespace(config=SecurityConfig())
    assert not hasattr(bare, "guard_decorator")
    assert _collect_route_configs(bare) is None
    assert _route_config_revision(bare) is None
    declared: Any = types.SimpleNamespace(guard_decorator=None)
    assert _collect_route_configs(declared) is None
    assert _route_config_revision(declared) is None
