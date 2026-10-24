import logging
import time
import uuid
from collections.abc import AsyncGenerator, AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import pytest
from redis.asyncio import Redis

from guard_core.core.initialization._redis_handler_members import (
    missing_redis_handler_members,
)
from guard_core.core.initialization.handler_initializer import HandlerInitializer
from guard_core.handlers.redis_handler import RedisHandlerBase, RedisManager
from guard_core.models import SecurityConfig
from guard_core.protocols.redis_protocol import RedisHandlerProtocol
from tests.protocol_only_redis import REDIS_URL, protocol_only_handler

IP = "198.51.100.77"


@pytest.fixture
async def handler() -> AsyncGenerator[Any, None]:
    async with protocol_only_handler() as fake:
        yield fake


async def test_a_handler_missing_methods_is_named_at_startup(
    handler: Any, caplog: pytest.LogCaptureFixture
) -> None:
    del handler.write_atomically
    del handler.owned_ban_state
    assert missing_redis_handler_members(handler) == [
        "owned_ban_state",
        "write_atomically",
    ]
    initializer = HandlerInitializer(
        handler.config.model_copy(update={"fail_on_misconfiguration": False}),
        redis_handler=handler,
    )
    with caplog.at_level(logging.WARNING):
        await initializer.initialize_redis_handlers()
    named = [r.getMessage() for r in caplog.records if "lacks" in r.getMessage()]
    assert len(named) == 1
    assert "owned_ban_state, write_atomically" in named[0]


async def test_a_handler_missing_one_method_refuses_to_start_when_asked(
    handler: Any,
) -> None:
    del handler.disown_ban
    config = handler.config.model_copy(update={"fail_on_misconfiguration": True})
    initializer = HandlerInitializer(config, redis_handler=handler)
    with pytest.raises(ValueError, match="lacks disown_ban,? "):
        await initializer.initialize_redis_handlers()


async def test_the_redis_manager_and_the_base_pass_the_startup_check(
    handler: Any,
) -> None:
    assert missing_redis_handler_members(RedisManager(handler.config)) == []
    assert isinstance(RedisManager(handler.config), RedisHandlerProtocol)


class _OwnPoolHandler(RedisHandlerBase):
    def __init__(self, config: SecurityConfig) -> None:
        self.config = config
        self._client: Redis | None = None

    async def initialize(self) -> None:
        self._client = Redis.from_url(REDIS_URL, decode_responses=True)

    @asynccontextmanager
    async def get_connection(self) -> AsyncIterator[Redis]:
        assert self._client is not None
        yield self._client

    async def close(self) -> None:
        assert self._client is not None
        await self._client.aclose()


async def test_a_subclass_of_the_base_gets_every_default() -> None:
    config = SecurityConfig(
        enable_redis=True,
        redis_url=REDIS_URL,
        redis_prefix=f"wp69base:{uuid.uuid4().hex}:",
    )
    own = _OwnPoolHandler(config)
    assert missing_redis_handler_members(own) == []
    await own.initialize()
    try:
        assert await own.set_key("ns", "k", "v")
        assert await own.get_key("ns", "k") == "v"
        assert await own.get_many([("ns", "k"), ("ns", "none")]) == ["v", None]
        assert await own.set_key_if_absent("ns", "k", "w") is False
        assert await own.incr("ns", "n") == 1
        now = time.time()
        assert await own.record_sliding_window_hit("w", "k", now, now - 60, 60) == 1
        assert await own.count_sliding_window_hits("w", "k", now - 60) == 1
        assert await own.write_ban_extending_only(
            "banned_ips", IP, str(now + 60), 60, version=("v", "c")
        ) == pytest.approx(now + 60)
        assert await own.delete_pattern("*") == 4
    finally:
        await own.close()


def test_the_base_reuses_the_managers_own_implementation() -> None:
    for name in ("record_sliding_window_hit", "write_ban_extending_only", "get_many"):
        assert getattr(RedisHandlerBase, name) is getattr(RedisManager, name)


def test_a_subclass_of_the_base_is_not_the_manager_singleton() -> None:
    config = SecurityConfig(enable_redis=True, redis_url=REDIS_URL)
    first, second = _OwnPoolHandler(config), _OwnPoolHandler(config)
    assert first is not second
    assert first is not RedisManager(config)
