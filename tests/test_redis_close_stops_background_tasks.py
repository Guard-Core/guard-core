import asyncio
import gc
import warnings
from collections.abc import AsyncIterator, Awaitable, Callable
from unittest.mock import AsyncMock, MagicMock

import pytest
from redis.asyncio.connection import Connection

from guard_core.core.initialization.handler_initializer import HandlerInitializer
from guard_core.handlers.cloud_handler import CloudManager
from guard_core.handlers.cloud_ip_stores import RedisCloudIpStore
from guard_core.handlers.redis_handler import RedisManager
from guard_core.models import SecurityConfig
from tests.conftest import REDIS_URL, suite_redis_prefix

Start = Callable[[SecurityConfig, RedisManager], Awaitable[asyncio.Task[None] | None]]


@pytest.fixture
async def config() -> SecurityConfig:
    return SecurityConfig(
        enable_redis=True,
        redis_url=REDIS_URL,
        redis_prefix=suite_redis_prefix("wp420tasks"),
        enable_agent=True,
        agent_api_key="test-api-key",
        enable_dynamic_rules=True,
        lazy_init=True,
        block_cloud_providers={"AWS"},
    )


@pytest.fixture
async def redis(config: SecurityConfig) -> AsyncIterator[RedisManager]:
    manager = RedisManager(config)
    await manager.initialize()
    assert manager._redis is not None
    await manager._redis.connection_pool.disconnect()
    yield manager
    await manager.close()


async def _close_while_the_task_is_connecting(
    redis: RedisManager,
    monkeypatch: pytest.MonkeyPatch,
    start: Callable[[], Awaitable[asyncio.Task[None] | None]],
) -> None:
    monkeypatch.setattr(
        "guard_core.handlers.cloud_handler._fetch_provider_ranges",
        AsyncMock(return_value=(set(), {})),
    )
    connecting = asyncio.Event()
    release = asyncio.Event()
    original_connect = Connection.connect
    assert redis._redis is not None
    own_port = redis._redis.connection_pool.connection_kwargs["port"]

    async def connect_held(self: Connection, *args: object, **kwargs: object) -> None:
        connecting.set()
        await release.wait()
        if self.port != own_port:
            raise ConnectionError(f"the test only connects to port {own_port}")
        await original_connect(self)

    monkeypatch.setattr(Connection, "connect", connect_held)
    task = await start()
    await asyncio.wait_for(connecting.wait(), 10)

    await redis.close()
    release.set()
    if task is not None:
        await asyncio.wait({task}, timeout=3)
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        gc.collect()
    assert [str(w.message) for w in caught if "unclosed" in str(w.message)] == []


async def test_closing_redis_stops_a_cloud_refresh_that_is_still_connecting(
    config: SecurityConfig, redis: RedisManager, monkeypatch: pytest.MonkeyPatch
) -> None:
    cloud = CloudManager()
    cloud.redis_handler = redis
    cloud.set_store(RedisCloudIpStore(redis))

    async def start() -> asyncio.Task[None] | None:
        await cloud.schedule_refresh({"AWS"})
        return cloud._refresh_task

    await _close_while_the_task_is_connecting(redis, monkeypatch, start)


async def test_closing_redis_stops_a_lazy_init_that_is_still_connecting(
    config: SecurityConfig, redis: RedisManager, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(redis, "initialize", AsyncMock())
    initializer = HandlerInitializer(
        config=config,
        redis_handler=redis,
        geo_ip_handler=None,
        rate_limit_handler=MagicMock(initialize_redis=AsyncMock()),
    )

    async def start() -> asyncio.Task[None] | None:
        await initializer._initialize_cloud_and_geo_redis(redis)
        return initializer._lazy_init_task

    await _close_while_the_task_is_connecting(redis, monkeypatch, start)


async def test_closing_redis_stops_the_dynamic_rule_loop_that_is_still_connecting(
    config: SecurityConfig, redis: RedisManager, monkeypatch: pytest.MonkeyPatch
) -> None:
    from guard_core.handlers.dynamic_rule_handler import DynamicRuleManager

    manager = DynamicRuleManager(config)
    await manager.initialize_redis(redis)
    manager.agent_handler = MagicMock(get_dynamic_rules=AsyncMock(return_value=None))

    async def start() -> asyncio.Task[None] | None:
        manager.update_task = asyncio.create_task(manager._rule_update_loop())
        return manager.update_task

    await _close_while_the_task_is_connecting(redis, monkeypatch, start)
