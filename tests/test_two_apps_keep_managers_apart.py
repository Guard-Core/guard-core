import asyncio
import gc
import logging
import tempfile
import uuid
from collections.abc import AsyncGenerator
from dataclasses import dataclass
from datetime import datetime, timezone
from ipaddress import ip_network
from pathlib import Path
from typing import Any, BinaryIO, Protocol
from unittest.mock import AsyncMock, Mock, patch

import pytest
from redis.asyncio import Redis

from guard_core.core.checks.implementations.cloud_ip_refresh import CloudIpRefreshCheck
from guard_core.core.checks.implementations.cloud_provider import CloudProviderCheck
from guard_core.core.initialization.handler_initializer import HandlerInitializer
from guard_core.handlers import cloud_handler as cloud_module
from guard_core.handlers import suspatterns_handler as suspatterns_module
from guard_core.handlers.cloud_handler import CloudManager, cloud_handler_for
from guard_core.handlers.dynamic_rule_handler import DynamicRuleManager
from guard_core.handlers.ipban_handler import ip_ban_manager_for
from guard_core.handlers.ipinfo_handler import IPInfoManager
from guard_core.handlers.redis_handler import RedisManager, close_redis_client
from guard_core.handlers.security_headers_handler import security_headers_manager
from guard_core.handlers.suspatterns_handler import (
    SusPatternsManager,
    sus_patterns_manager_for,
)
from guard_core.models import DynamicRules, SecurityConfig
from guard_core.protocols.redis_protocol import RedisHandlerProtocol
from guard_core.utils import detect_penetration_attempt
from tests.conftest import MockGuardRequest, suite_redis_prefix
from tests.geo_fixture import country_database_bytes
from tests.protocol_only_redis import REDIS_URL

CLOUD_RANGE = "198.51.100.0/24"
CLOUD_IP = "198.51.100.77"


@dataclass
class _App:
    config: SecurityConfig
    redis: RedisManager
    middleware: Mock
    initializer: HandlerInitializer
    geo: IPInfoManager


class _FakeSession:
    downloads = 0


async def _fake_download_body(
    self: IPInfoManager, session: object, headers: dict[str, str], sink: BinaryIO
) -> None:
    _FakeSession.downloads += 1
    sink.write(country_database_bytes("XX"))


async def _start_app(prefix: str, database_path: Path, **settings: object) -> _App:
    geo = IPInfoManager(token="token-shared", db_path=database_path)
    config = SecurityConfig(
        enable_redis=True,
        redis_url=REDIS_URL,
        redis_prefix=prefix,
        enable_dynamic_rules=False,
        lazy_init=False,
        block_cloud_providers={"AWS"},
        blocked_countries=["XX"],
        geo_ip_handler=geo,
        security_headers={"enabled": True, "custom": {"X-App": prefix.rstrip(":")}},
        **settings,
    )
    redis = RedisManager(config)
    middleware = Mock()
    middleware.config = config
    middleware.logger = logging.getLogger("two_apps_managers")
    initializer = HandlerInitializer(config, redis_handler=redis, geo_ip_handler=geo)
    await initializer.initialize_redis_handlers()
    return _App(config, redis, middleware, initializer, geo)


class _FakeProviders:
    fetched: list[str] = []

    @classmethod
    async def fetch(cls, provider: str) -> tuple[set[Any], dict[str, str]]:
        cls.fetched.append(provider)
        return {ip_network(CLOUD_RANGE)}, {CLOUD_RANGE: "region-1"}


@pytest.fixture
async def apps() -> AsyncGenerator[tuple[_App, _App], None]:
    tag = uuid.uuid4().hex[:8]
    _FakeProviders.fetched.clear()
    _FakeSession.downloads = 0
    with (
        tempfile.TemporaryDirectory() as directory,
        patch.object(cloud_module, "_fetch_provider_ranges", _FakeProviders.fetch),
        patch.object(IPInfoManager, "_download_body", _fake_download_body),
    ):
        database = Path(directory) / "country_asn.mmdb"
        app_a = await _start_app(f"a{tag}:", database)
        app_b = await _start_app(f"b{tag}:", database)
        try:
            yield app_a, app_b
        finally:
            for app in (app_a, app_b):
                await app.redis.delete_pattern("*")
                await app.redis.close()


async def _keys(prefix: str) -> set[str]:
    client = Redis.from_url(REDIS_URL, decode_responses=True)
    try:
        return {key async for key in client.scan_iter(match=f"{prefix}*", count=500)}
    finally:
        await close_redis_client(client)


class _HasRedisHandler(Protocol):
    @property
    def redis_handler(self) -> RedisHandlerProtocol | None: ...


def _prefix_of(manager: _HasRedisHandler) -> str:
    handler = manager.redis_handler
    assert handler is not None
    return str(handler.config.redis_prefix)


async def test_custom_patterns_of_each_app_land_under_its_own_prefix(
    apps: tuple[_App, _App],
) -> None:
    app_a, app_b = apps
    manager_a = sus_patterns_manager_for(app_a.config)
    manager_b = sus_patterns_manager_for(app_b.config)
    assert manager_a is not manager_b
    assert _prefix_of(manager_a) == app_a.config.redis_prefix
    assert _prefix_of(manager_b) == app_b.config.redis_prefix

    assert await manager_a.add_pattern(r"customAonly_[0-9]{3}", custom=True)
    assert await manager_b.add_pattern(r"customBonly_[0-9]{3}", custom=True)

    stored_a = await app_a.redis.get_key("patterns", "custom")
    stored_b = await app_b.redis.get_key("patterns", "custom")
    assert stored_a is not None
    assert stored_b is not None
    assert "customAonly" in stored_a
    assert "customBonly" not in stored_a
    assert "customBonly" in stored_b
    assert "customAonly" not in stored_b
    assert await manager_a.get_custom_patterns() == [r"customAonly_[0-9]{3}"]
    assert await manager_b.get_custom_patterns() == [r"customBonly_[0-9]{3}"]


async def test_each_app_detects_with_its_own_custom_patterns_and_settings(
    apps: tuple[_App, _App],
) -> None:
    app_a, app_b = apps
    manager_a = sus_patterns_manager_for(app_a.config)
    manager_b = sus_patterns_manager_for(app_b.config)
    assert await manager_a.add_pattern(r"customAonly_[0-9]{3}", custom=True)
    assert await manager_b.add_pattern(r"customBonly_[0-9]{3}", custom=True)

    def request(marker: str) -> MockGuardRequest:
        return MockGuardRequest(path=f"/search?q={marker}", client_host="203.0.113.9")

    state_a, state_b = manager_a._detection_state, manager_b._detection_state
    assert state_a is not state_b
    for _ in range(2):
        assert (
            await detect_penetration_attempt(request("customAonly_123"), app_a.config)
        ).is_threat
        assert not (
            await detect_penetration_attempt(request("customAonly_123"), app_b.config)
        ).is_threat
        assert (
            await detect_penetration_attempt(request("customBonly_123"), app_b.config)
        ).is_threat
        assert not (
            await detect_penetration_attempt(request("customBonly_123"), app_a.config)
        ).is_threat
    assert manager_a._detection_state is state_a
    assert manager_b._detection_state is state_b
    assert manager_a._config is app_a.config
    assert manager_b._config is app_b.config


async def test_dynamic_rules_of_each_app_keep_their_config_and_state_apart(
    apps: tuple[_App, _App],
) -> None:
    app_a, app_b = apps
    rules_a = DynamicRuleManager(app_a.config)
    rules_b = DynamicRuleManager(app_b.config)
    assert rules_a is not rules_b
    assert rules_a.config is app_a.config
    assert rules_b.config is app_b.config
    await rules_a.initialize_redis(app_a.redis)
    await rules_b.initialize_redis(app_b.redis)

    await rules_a._persist_last_known_rules(
        DynamicRules(
            rule_id="rule-for-a", version=1, timestamp=datetime.now(timezone.utc)
        )
    )
    assert any("dynamic_rules" in key for key in await _keys(app_a.config.redis_prefix))
    assert not any(
        "dynamic_rules" in key for key in await _keys(app_b.config.redis_prefix)
    )

    created: list[str] = []
    await rules_a._apply_pattern_rules([r"ruleAonly_[0-9]{4}"], created)
    assert created == [r"ruleAonly_[0-9]{4}"]
    assert r"ruleAonly_[0-9]{4}" in sus_patterns_manager_for(app_a.config).patterns
    assert r"ruleAonly_[0-9]{4}" not in sus_patterns_manager_for(app_b.config).patterns


async def test_cloud_ranges_are_cached_under_each_prefix_and_downloaded_once(
    apps: tuple[_App, _App],
) -> None:
    app_a, app_b = apps
    cloud_a = cloud_handler_for(app_a.config)
    cloud_b = cloud_handler_for(app_b.config)
    assert cloud_a is not cloud_b
    assert cloud_a.redis_handler is app_a.redis
    assert cloud_b.redis_handler is app_b.redis
    assert _FakeProviders.fetched == ["AWS"]
    assert cloud_a.ip_ranges is cloud_b.ip_ranges

    for app in (app_a, app_b):
        stored = await app.redis.get_key("cloud_ip_v2", "AWS")
        assert stored is not None
        assert CLOUD_RANGE in stored
    assert any("cloud_ip_v2" in key for key in await _keys(app_a.config.redis_prefix))
    assert any("cloud_ip_v2" in key for key in await _keys(app_b.config.redis_prefix))

    await app_a.redis.delete("cloud_ip_v2", "AWS")
    await app_b.redis.delete("cloud_ip_v2", "AWS")
    await cloud_a.refresh_async({"AWS"}, ttl=3600)
    assert await app_a.redis.get_key("cloud_ip_v2", "AWS") is not None
    assert await app_b.redis.get_key("cloud_ip_v2", "AWS") is None

    assert CloudProviderCheck(app_a.middleware).cloud_handler is cloud_a
    assert CloudProviderCheck(app_b.middleware).cloud_handler is cloud_b
    assert cloud_a.is_cloud_ip(CLOUD_IP, {"AWS"})
    assert cloud_b.is_cloud_ip(CLOUD_IP, {"AWS"})


async def test_the_periodic_refresh_of_each_app_runs_on_its_own_store(
    apps: tuple[_App, _App],
) -> None:
    app_a, app_b = apps
    await app_a.redis.delete("cloud_ip_v2", "AWS")
    await app_b.redis.delete("cloud_ip_v2", "AWS")
    for app in (app_a, app_b):
        app.middleware.last_cloud_ip_refresh = 0
        app.middleware.refresh_cloud_ip_ranges = AsyncMock()
        app.middleware.route_resolver.get_cloud_providers_to_check = Mock(
            return_value={"AWS"}
        )

    check = CloudIpRefreshCheck(app_b.middleware)
    assert await check.check(MockGuardRequest(path="/x")) is None
    for _ in range(100):
        if await app_b.redis.get_key("cloud_ip_v2", "AWS") is not None:
            break
        await asyncio.sleep(0.05)

    app_b.middleware.refresh_cloud_ip_ranges.assert_not_awaited()
    assert await app_b.redis.get_key("cloud_ip_v2", "AWS") is not None
    assert await app_a.redis.get_key("cloud_ip_v2", "AWS") is None


async def test_the_geo_database_is_downloaded_once_and_cached_under_each_prefix(
    apps: tuple[_App, _App],
) -> None:
    app_a, app_b = apps
    geo = app_a.geo
    assert app_b.geo is geo
    assert _FakeSession.downloads == 1
    assert geo.is_initialized
    for app in (app_a, app_b):
        assert await app.redis.get_key("ipinfo", "database") is not None

    await app_a.redis.delete("ipinfo", "database")
    await app_b.redis.delete("ipinfo", "database")
    await geo.refresh()
    for app in (app_a, app_b):
        assert await app.redis.get_key("ipinfo", "database") is not None


async def test_response_headers_follow_the_config_of_each_app(
    apps: tuple[_App, _App],
) -> None:
    app_a, app_b = apps
    for _ in range(2):
        for app in (app_a, app_b):
            headers = await security_headers_manager.get_headers(
                request_path="/x", config=app.config
            )
            assert headers["X-App"] == app.config.redis_prefix.rstrip(":")


async def test_one_config_gives_one_manager_of_each_kind(
    apps: tuple[_App, _App],
) -> None:
    app_a, app_b = apps
    for app in (app_a, app_b):
        assert sus_patterns_manager_for(app.config) is sus_patterns_manager_for(
            app.config, bind=True
        )
        assert DynamicRuleManager(app.config) is DynamicRuleManager(app.config)
        assert cloud_handler_for(app.config) is cloud_handler_for(app.config, bind=True)
        assert ip_ban_manager_for(app.config) is ip_ban_manager_for(
            app.config, bind=True
        )
    assert (
        sus_patterns_manager_for(app_a.config)
        is suspatterns_module.sus_patterns_handler
    )
    assert cloud_handler_for(app_a.config) is cloud_module.cloud_handler
    assert isinstance(sus_patterns_manager_for(app_b.config), SusPatternsManager)
    assert isinstance(cloud_handler_for(app_b.config), CloudManager)


async def test_three_apps_each_keep_their_own_managers_after_a_collection(
    apps: tuple[_App, _App],
) -> None:
    app_a, app_b = apps
    app_c = await _start_app(suite_redis_prefix("c"), app_a.geo.db_path)
    try:
        for app in (app_a, app_b, app_c):
            await DynamicRuleManager(app.config).initialize_redis(app.redis)
        gc.collect()
        for app in (app_a, app_b, app_c):
            prefix = app.config.redis_prefix
            assert _prefix_of(sus_patterns_manager_for(app.config)) == prefix
            assert _prefix_of(ip_ban_manager_for(app.config)) == prefix
            assert _prefix_of(DynamicRuleManager(app.config)) == prefix
            assert cloud_handler_for(app.config).redis_handler is app.redis
    finally:
        await app_c.redis.delete_pattern("*")
        await app_c.redis.close()


async def test_apps_on_one_prefix_share_the_default_managers() -> None:
    prefix = suite_redis_prefix("same")
    configs = [
        SecurityConfig(
            enable_redis=True,
            redis_url=REDIS_URL,
            redis_prefix=prefix,
            enable_dynamic_rules=False,
        )
        for _ in range(2)
    ]
    for config in configs:
        HandlerInitializer(config)
    first, second = configs
    assert sus_patterns_manager_for(first) is sus_patterns_manager_for(second)
    assert sus_patterns_manager_for(first) is suspatterns_module.sus_patterns_handler
    assert cloud_handler_for(first) is cloud_handler_for(second)
    assert ip_ban_manager_for(first) is ip_ban_manager_for(second)
    assert DynamicRuleManager(first) is not DynamicRuleManager(second)
