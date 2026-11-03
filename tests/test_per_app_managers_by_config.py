import gc
import logging
import sys
import tempfile
import uuid
import weakref
from pathlib import Path
from typing import Any
from unittest.mock import Mock, patch

from guard_core.core.events.metrics import MetricsCollector
from guard_core.core.initialization.handler_initializer import HandlerInitializer
from guard_core.core.responses.context import ResponseContext
from guard_core.core.responses.factory import ErrorResponseFactory
from guard_core.handlers import _suspatterns_enhanced as enhanced_module
from guard_core.handlers import cloud_handler as cloud_module
from guard_core.handlers import ipban_handler as ipban_module
from guard_core.handlers import suspatterns_handler as suspatterns_module
from guard_core.handlers.cloud_handler import cloud_handler_for
from guard_core.handlers.dynamic_rule_handler import DynamicRuleManager
from guard_core.handlers.ipban_handler import ip_ban_manager_for
from guard_core.handlers.ipinfo_handler import IPInfoManager
from guard_core.handlers.redis_handler import RedisManager, close_redis_client
from guard_core.handlers.security_headers_handler import security_headers_manager
from guard_core.handlers.suspatterns_handler import sus_patterns_manager_for
from guard_core.models import SecurityConfig
from guard_core.utils import detect_penetration_attempt
from tests.conftest import MockGuardRequest, suite_redis_prefix
from tests.protocol_only_redis import REDIS_URL

_LOOKUP_FUNCTIONS = frozenset(
    {
        "sus_patterns_manager_for",
        "active_sus_patterns",
        "scanning_with",
        "ip_ban_manager_for",
        "cloud_handler_for",
    }
)
_MANAGER_REGISTRY_FILE = "app_managers.py"


def _config(prefix: str | None = None, **settings: Any) -> SecurityConfig:
    redis: dict[str, Any]
    if prefix is not None:
        redis = {"enable_redis": True, "redis_url": REDIS_URL, "redis_prefix": prefix}
    else:
        redis = {"enable_redis": False}
    return SecurityConfig(
        enable_dynamic_rules=False,
        enable_penetration_detection=True,
        lazy_init=False,
        **redis,
        **settings,
    )


def _bind(config: SecurityConfig, redis: RedisManager | None = None) -> dict[str, Any]:
    HandlerInitializer(config, redis_handler=redis)
    return {
        "patterns": sus_patterns_manager_for(config),
        "ban": ip_ban_manager_for(config),
        "dynamic": DynamicRuleManager(config),
        "cloud": cloud_handler_for(config),
    }


def _request(marker: str = "hello") -> MockGuardRequest:
    return MockGuardRequest(path=f"/items?q={marker}", client_host="203.0.113.9")


async def test_two_apps_without_redis_alternate_without_rebuilding_detection() -> None:
    configs = [_config(detection_semantic_threshold=t) for t in (0.5, 0.9)]
    for config in configs:
        HandlerInitializer(config)
    builds: list[int] = []
    real = enhanced_module._build_enhanced_detection_state

    def counting(config: Any, redaction_names: Any = None) -> Any:
        builds.append(1)
        return real(config, redaction_names)

    with (
        patch.object(enhanced_module, "_build_enhanced_detection_state", counting),
        patch.object(suspatterns_module, "_build_enhanced_detection_state", counting),
    ):
        for _ in range(2):
            for config in configs:
                await detect_penetration_attempt(_request(), config)
        builds.clear()
        for _ in range(10):
            for config in configs:
                await detect_penetration_attempt(_request(), config)
    assert builds == []
    thresholds = [
        sus_patterns_manager_for(config)._detection_state.semantic_threshold
        for config in configs
    ]
    assert thresholds == [0.5, 0.9]


async def test_a_no_redis_app_does_not_move_the_prefix_the_default_serves() -> None:
    tag = uuid.uuid4().hex[:8]
    config_a, config_c, config_d = (
        _config(f"a{tag}:"),
        _config(),
        _config(f"d{tag}:"),
    )
    redis_a, redis_d = RedisManager(config_a), RedisManager(config_d)
    managers_a = _bind(config_a, redis_a)
    managers_c = _bind(config_c)
    managers_d = _bind(config_d, redis_d)
    for kind in managers_a:
        assert managers_c[kind] is not managers_a[kind], kind
        assert managers_d[kind] is not managers_a[kind], kind
        assert managers_d[kind] is not managers_c[kind], kind
    assert managers_a["patterns"] is suspatterns_module.sus_patterns_handler
    assert managers_a["ban"] is ipban_module.ip_ban_manager
    assert managers_a["cloud"] is cloud_module.cloud_handler
    assert sus_patterns_manager_for(config_d) is managers_d["patterns"]
    assert ip_ban_manager_for(config_d) is managers_d["ban"]
    assert DynamicRuleManager(config_d).config is config_d
    assert DynamicRuleManager(config_c).config is config_c


async def test_the_managers_of_a_no_redis_app_live_as_long_as_the_app() -> None:
    config_a, config_c = _config(suite_redis_prefix("a")), _config()
    _bind(config_a, RedisManager(config_a))
    managers = _bind(config_c)
    refs = {kind: weakref.ref(manager) for kind, manager in managers.items()}
    del managers
    gc.collect()
    assert all(ref() is not None for ref in refs.values())
    assert sus_patterns_manager_for(config_c) is refs["patterns"]()
    assert ip_ban_manager_for(config_c) is refs["ban"]()
    assert DynamicRuleManager(config_c) is refs["dynamic"]()
    assert cloud_handler_for(config_c) is refs["cloud"]()


async def test_a_warm_request_resolves_its_manager_in_one_call_without_a_lookup() -> (
    None
):
    config = _config()
    HandlerInitializer(config)
    for _ in range(3):
        await detect_penetration_attempt(_request(), config)
    resolution_calls = 0
    lookups: set[str] = set()
    calls_made_by_it = 0
    c_calls_made_by_it = 0
    name = "_ensure_detection_singleton_configured"

    def profile(frame: Any, event: str, arg: Any) -> None:
        nonlocal resolution_calls, calls_made_by_it, c_calls_made_by_it
        if event == "call":
            if frame.f_code.co_name == name:
                resolution_calls += 1
            elif (
                frame.f_code.co_name in _LOOKUP_FUNCTIONS
                or Path(frame.f_code.co_filename).name == _MANAGER_REGISTRY_FILE
            ):
                lookups.add(frame.f_code.co_name)
            if frame.f_back is not None and frame.f_back.f_code.co_name == name:
                calls_made_by_it += 1
        elif event == "c_call" and frame.f_code.co_name == name:
            c_calls_made_by_it += 1

    request = _request()
    sys.setprofile(profile)
    try:
        await detect_penetration_attempt(request, config)
    finally:
        sys.setprofile(None)
    assert resolution_calls == 1
    assert lookups == set()
    assert calls_made_by_it == 0
    assert c_calls_made_by_it == 0


async def test_one_ipinfo_manager_per_database_file() -> None:
    IPInfoManager._instance = None
    with tempfile.TemporaryDirectory() as directory:
        shared = Path(directory) / "shared.mmdb"
        other = Path(directory) / "other.mmdb"
        first = IPInfoManager(token="first-token", db_path=shared, max_age=86400)
        second = IPInfoManager(
            token="second-token",
            db_path=Path(directory) / "." / "shared.mmdb",
            max_age=2592000,
        )
        third = IPInfoManager(token="third-token", db_path=shared, max_age=3600)
        elsewhere = IPInfoManager(token="other-token", db_path=other)
        assert second is first
        assert third is first
        assert first.token == "first-token"
        assert first._max_age == 3600
        assert elsewhere is not first
        assert elsewhere.token == "other-token"
        assert elsewhere.db_path == other
    IPInfoManager._instance = None


async def test_a_reset_instance_never_hands_out_a_closed_reader() -> None:
    IPInfoManager._instance = None
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "reset.mmdb"
        manager = IPInfoManager(token="tok", db_path=path)
        closed = Mock()
        manager.reader = closed
        closed.close()
        IPInfoManager._instance = None
        fresh = IPInfoManager(token="tok", db_path=path)
        assert fresh is not manager
        assert fresh.reader is None
        assert not fresh.is_initialized
    IPInfoManager._instance = None


async def test_two_response_factories_write_the_override_under_their_own_prefix() -> (
    None
):
    tag = uuid.uuid4().hex[:8]
    apps: list[tuple[SecurityConfig, RedisManager, ErrorResponseFactory]] = []
    for prefix in (f"ha{tag}:", f"hb{tag}:"):
        custom = {"X-App": prefix}
        config = _config(
            prefix,
            security_headers={"enabled": True, "custom": custom},
        )
        redis = RedisManager(config)
        initializer = HandlerInitializer(config, redis_handler=redis)
        security_headers_manager.configure(enabled=True, custom_headers=custom)
        await initializer.initialize_redis_handlers()
        factory = ErrorResponseFactory(
            ResponseContext(
                config=config,
                logger=logging.getLogger("two_apps_headers"),
                metrics_collector=MetricsCollector(None, config),
                redis_handler=redis,
            )
        )
        apps.append((config, redis, factory))
    try:
        for config, redis, factory in apps:
            manager = factory.security_headers_manager
            assert manager is not security_headers_manager
            assert manager.redis_handler is redis
            headers = await manager.get_headers("/x", config=config)
            assert headers["X-App"] == config.redis_prefix
        security_headers_manager.configure(frame_options="DENY", override_apps=True)
        for config, _redis, factory in apps:
            headers = await factory.security_headers_manager.get_headers(
                "/x", config=config
            )
            assert headers["X-Frame-Options"] == "DENY"
        for config, _redis, _factory in apps:
            overrides = await _override_keys(config.redis_prefix)
            assert len(overrides) == 1
    finally:
        for _, redis, _ in apps:
            await redis.delete_pattern("*")
            await redis.close()


async def _override_keys(prefix: str) -> list[str]:
    from redis.asyncio import Redis

    client = Redis.from_url(REDIS_URL, decode_responses=True)
    try:
        return [
            key
            async for key in client.scan_iter(match=f"{prefix}*override*", count=500)
        ]
    finally:
        await close_redis_client(client)
