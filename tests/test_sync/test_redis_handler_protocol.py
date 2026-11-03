import types
from collections.abc import Generator
from typing import Any, Protocol, runtime_checkable
from unittest.mock import MagicMock

import pytest
from typing_extensions import get_protocol_members

from guard_core.models import SyncSecurityConfig
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.sync.core.checks._shared_strikes import (
    forget_shared_detection_strikes,
    read_shared_detection_categories,
    record_shared_detection_strikes,
)
from guard_core.sync.core.checks.factory import (
    _collect_route_configs,
    _route_config_revision,
)
from guard_core.sync.core.initialization.handler_initializer import HandlerInitializer
from guard_core.sync.handlers._dynamic_rule_application import RuleSideEffects
from guard_core.sync.handlers.behavior_handler import BehaviorRule, BehaviorTracker
from guard_core.sync.handlers.cloud_ip_stores import RedisCloudIpStore
from guard_core.sync.handlers.dynamic_rule_handler import DynamicRuleManager
from guard_core.sync.handlers.ipban_handler import IPBanManager, ip_ban_manager
from guard_core.sync.handlers.ratelimit_handler import RateLimitManager
from guard_core.sync.handlers.security_headers_handler import SecurityHeadersManager
from guard_core.sync.handlers.suspatterns_handler import SusPatternsManager
from guard_core.sync.protocols.middleware_protocol import SyncGuardMiddlewareProtocol
from guard_core.sync.protocols.redis_protocol import SyncRedisHandlerProtocol
from tests.test_sync.conftest import SyncMockGuardRequest
from tests.test_sync.protocol_only_redis import MEMBERS, protocol_only_handler

IP = "198.51.100.77"
NETWORK = "203.0.113.0/24"
DAY = 86400


@runtime_checkable
class RecordingRedisHandler(SyncRedisHandlerProtocol, Protocol):
    used: set[str]


@pytest.fixture
def handler() -> Generator[RecordingRedisHandler, None]:
    with protocol_only_handler() as fake:
        assert isinstance(fake, RecordingRedisHandler)
        yield fake


def _fresh_ban_manager(handler: RecordingRedisHandler) -> IPBanManager:
    ip_ban_manager.config = handler.config
    ip_ban_manager.redis_handler = handler
    ip_ban_manager.banned_ips.clear()
    ip_ban_manager.banned_networks.clear()
    return ip_ban_manager


def _request() -> SyncMockGuardRequest:
    return SyncMockGuardRequest(path="/x", client_host=IP)


def _error(status: int, message: str) -> GuardResponse:
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


def test_bans_run_on_a_protocol_only_handler(
    handler: RecordingRedisHandler,
) -> None:
    manager = _fresh_ban_manager(handler)
    assert manager.ban_ip(IP, 300, "wp69")
    manager.banned_ips.clear()
    assert manager.is_ip_banned(IP)
    manager.unban_ip(IP)
    manager.banned_ips.clear()
    assert not manager.is_ip_banned(IP)


def test_rule_owned_bans_run_on_a_protocol_only_handler(
    handler: RecordingRedisHandler,
) -> None:
    manager = _fresh_ban_manager(handler)
    DynamicRuleManager._instance = None
    worker = DynamicRuleManager(handler.config)
    worker.redis_handler = handler
    effects = RuleSideEffects()
    for target in (IP, NETWORK):
        worker._apply_ip_bans([target], DAY, effects.created_bans, effects.skipped)
    assert manager.owned_rule_ban_targets()
    assert manager.rule_owns_live_ban(f"banned_ips:{IP}")
    assert manager.revoke_rule_ban(IP) in (0, 1, 2, 3)
    manager.disown_rule_ban(NETWORK)
    assert isinstance(manager.purge_rule_owned_bans(), dict)
    assert {
        "write_ban_extending_only",
        "owned_ban_members",
        "owned_ban_state",
        "purge_owned_ban",
        "disown_ban",
    } <= handler.used


def test_rate_limits_run_on_a_protocol_only_handler(
    handler: RecordingRedisHandler,
) -> None:
    limiter = RateLimitManager(handler.config)
    limiter.initialize_redis(handler)
    first = limiter.check_rate_limit(
        _request(), IP, _error, rate_limit=1, rate_limit_window=60
    )
    second = limiter.check_rate_limit(
        _request(), IP, _error, rate_limit=1, rate_limit_window=60
    )
    assert first is None and second is not None
    from guard_core.sync.handlers.ratelimit_handler import (
        forget_shared_violations,
        record_shared_violation,
    )

    assert record_shared_violation(handler, IP) >= 1
    forget_shared_violations(handler, IP)
    limiter.reset()
    assert {"record_sliding_window_hit", "delete", "delete_pattern"} <= handler.used
    assert "get_connection" in handler.used


def test_behavior_rules_run_on_a_protocol_only_handler(
    handler: RecordingRedisHandler,
) -> None:
    tracker = BehaviorTracker(handler.config)
    tracker.initialize_redis(handler)
    rule = BehaviorRule("usage", threshold=2, window=60)
    for _ in range(3):
        tracker.track_endpoint_usage("/probe", IP, rule)
    assert tracker.track_endpoint_usage("/probe", IP, rule, record=False)
    assert tracker.count_recent_rule_hits(IP, 60) >= 1
    assert {
        "record_sliding_window_hit",
        "count_sliding_window_hits",
        "sum_indexed_window_hits",
    } <= handler.used


def test_detection_strikes_run_on_a_protocol_only_handler(
    handler: RecordingRedisHandler,
) -> None:
    middleware: Any = types.SimpleNamespace(
        config=handler.config,
        rate_limit_handler=types.SimpleNamespace(redis_handler=handler),
    )
    strikes = record_shared_detection_strikes(middleware, IP, ["xss", "sqli"], 60, 100)
    assert strikes is not None and strikes.total == 1
    assert read_shared_detection_categories(handler, IP, 60) == ["sqli", "xss"]
    forget_shared_detection_strikes(middleware, IP)
    assert read_shared_detection_categories(handler, IP, 60) == []
    assert handler.detection_correlation_keys(IP)
    assert {
        "record_detection_strikes",
        "read_detection_categories",
        "forget_detection_strikes",
        "detection_correlation_keys",
    } <= handler.used


def test_cloud_ranges_headers_and_patterns_run_on_a_protocol_only_handler(
    handler: RecordingRedisHandler,
) -> None:
    store = RedisCloudIpStore(handler)
    store.set("AWS", {"203.0.113.0/24|eu"}, ttl=60)
    assert store.get("AWS") == {"203.0.113.0/24|eu"}
    store.clear()
    assert store.get("AWS") is None

    headers = SecurityHeadersManager()
    headers.configure(csp={"default-src": ["'self'"]})
    headers.initialize_redis(handler, handler.config)
    headers.reset()

    SusPatternsManager._instance = None
    patterns = SusPatternsManager()
    patterns.initialize_redis(handler)
    assert SusPatternsManager.add_pattern("wp69-pin", custom=True)
    assert SusPatternsManager.remove_pattern("wp69-pin", custom=True)
    assert {"get_key", "set_key", "keys", "delete", "get_many", "write_atomically"} <= (
        handler.used
    )


def test_the_initializer_runs_on_a_protocol_only_handler(
    handler: RecordingRedisHandler,
) -> None:
    IPBanManager._instance = None
    initializer = HandlerInitializer(handler.config, redis_handler=handler)
    initializer.initialize_redis_handlers()
    handler.initialize_agent(MagicMock())
    assert {"initialize", "initialize_agent", "set_key_if_absent"} <= handler.used


def test_the_middleware_protocol_declares_guard_decorator() -> None:
    assert "guard_decorator" in get_protocol_members(SyncGuardMiddlewareProtocol)


def test_a_middleware_without_guard_decorator_still_works() -> None:
    bare: Any = types.SimpleNamespace(config=SyncSecurityConfig())
    assert not hasattr(bare, "guard_decorator")
    assert _collect_route_configs(bare) is None
    assert _route_config_revision(bare) is None
    declared: Any = types.SimpleNamespace(guard_decorator=None)
    assert _collect_route_configs(declared) is None
    assert _route_config_revision(declared) is None
