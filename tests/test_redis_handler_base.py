import logging
import time
from collections.abc import AsyncGenerator, AsyncIterator
from contextlib import asynccontextmanager
from typing import Protocol, runtime_checkable

import pytest
from redis.asyncio import Redis

from guard_core.core.initialization._redis_handler_members import (
    missing_redis_handler_members,
)
from guard_core.core.initialization.handler_initializer import HandlerInitializer
from guard_core.handlers.redis_handler import (
    RedisHandlerBase,
    RedisManager,
    close_redis_client,
)
from guard_core.models import SecurityConfig
from guard_core.protocols.redis_protocol import RedisHandlerProtocol
from tests.async_is_connected import async_false
from tests.conftest import suite_redis_prefix
from tests.protocol_only_redis import REDIS_URL, protocol_only_handler

IP = "198.51.100.77"


@runtime_checkable
class RecordingRedisHandler(RedisHandlerProtocol, Protocol):
    used: set[str]


@pytest.fixture
async def handler() -> AsyncGenerator[RecordingRedisHandler, None]:
    async with protocol_only_handler() as fake:
        assert isinstance(fake, RecordingRedisHandler)
        yield fake


async def test_a_handler_missing_methods_is_named_at_startup(
    handler: RecordingRedisHandler, caplog: pytest.LogCaptureFixture
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
    handler: RecordingRedisHandler,
) -> None:
    del handler.disown_ban
    config = handler.config.model_copy(update={"fail_on_misconfiguration": True})
    initializer = HandlerInitializer(config, redis_handler=handler)
    with pytest.raises(ValueError, match="lacks disown_ban,? "):
        await initializer.initialize_redis_handlers()


async def test_the_redis_manager_and_the_base_pass_the_startup_check(
    handler: RecordingRedisHandler,
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
        await close_redis_client(self._client)


async def test_a_subclass_of_the_base_gets_every_default() -> None:
    config = SecurityConfig(
        enable_redis=True,
        redis_url=REDIS_URL,
        redis_prefix=suite_redis_prefix("wp69base"),
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


def _singleton() -> object:
    return RedisManager._instance


def reset_singleton() -> None:
    RedisManager._instance = None


async def test_a_base_subclass_leaves_the_manager_singleton_alone() -> None:
    # D-112 item 1: RedisManager._instance stays the most recently constructed
    # and initialized RedisManager; a RedisHandlerBase subclass is never it.
    config = SecurityConfig(
        enable_redis=True,
        redis_url=REDIS_URL,
        redis_prefix=suite_redis_prefix("wp69inst"),
    )
    reset_singleton()
    own = _OwnPoolHandler(config)
    await own.initialize()
    try:
        assert _singleton() is None
        manager = RedisManager(config)
        assert _singleton() is manager
        assert manager is not own
        inherited = RedisHandlerBase(config)
        await inherited.initialize()
        try:
            assert _singleton() is manager
            assert RedisManager(config) is manager
            assert inherited is not manager
        finally:
            await inherited.close()
    finally:
        await own.close()
        reset_singleton()


class _OnlyTheClientAttribute:
    _redis = None


def test_is_connected_is_named_for_a_handler_with_neither_it_nor_a_client() -> None:
    assert "is_connected" in missing_redis_handler_members(object())
    assert "is_connected" not in missing_redis_handler_members(
        object(), recovery_armable=False
    )


def test_a_client_attribute_stands_in_for_is_connected() -> None:
    absent = missing_redis_handler_members(_OnlyTheClientAttribute())
    assert "is_connected" not in absent
    assert missing_redis_handler_members(RedisManager(SecurityConfig())) == []


async def test_a_handler_without_is_connected_is_named_when_redis_fails_open(
    handler: RecordingRedisHandler, caplog: pytest.LogCaptureFixture
) -> None:
    del handler.is_connected
    config = handler.config.model_copy(
        update={"redis_fail_open": True, "fail_on_misconfiguration": False}
    )
    with caplog.at_level(logging.WARNING):
        await HandlerInitializer(
            config, redis_handler=handler
        ).initialize_redis_handlers()
    named = [r.getMessage() for r in caplog.records if "lacks" in r.getMessage()]
    assert len(named) == 1
    assert "lacks is_connected," in named[0]


async def test_a_handler_without_is_connected_refuses_to_start_when_asked(
    handler: RecordingRedisHandler,
) -> None:
    del handler.is_connected
    config = handler.config.model_copy(
        update={"redis_fail_open": True, "fail_on_misconfiguration": True}
    )
    with pytest.raises(ValueError, match="lacks is_connected,"):
        await HandlerInitializer(
            config, redis_handler=handler
        ).initialize_redis_handlers()


async def test_a_handler_without_is_connected_starts_clean_when_redis_fails_closed(
    handler: RecordingRedisHandler, caplog: pytest.LogCaptureFixture
) -> None:
    del handler.is_connected
    config = handler.config.model_copy(
        update={"redis_fail_open": False, "fail_on_misconfiguration": True}
    )
    with caplog.at_level(logging.WARNING):
        await HandlerInitializer(
            config, redis_handler=handler
        ).initialize_redis_handlers()
    assert not [r for r in caplog.records if "lacks" in r.getMessage()]


async def test_an_async_is_connected_is_refused_at_startup_when_redis_fails_open(
    handler: RecordingRedisHandler, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(handler, "is_connected", async_false)
    config = handler.config.model_copy(
        update={"redis_fail_open": True, "fail_on_misconfiguration": True}
    )
    with pytest.raises(ValueError, match="without awaiting"):
        await HandlerInitializer(
            config, redis_handler=handler
        ).initialize_redis_handlers()


async def test_an_async_is_connected_is_warned_about_when_asked_to_start_anyway(
    handler: RecordingRedisHandler,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.setattr(handler, "is_connected", async_false)
    config = handler.config.model_copy(
        update={"redis_fail_open": True, "fail_on_misconfiguration": False}
    )
    with caplog.at_level(logging.WARNING):
        await HandlerInitializer(
            config, redis_handler=handler
        ).initialize_redis_handlers()
    named = [r for r in caplog.records if "without awaiting" in r.getMessage()]
    assert len(named) == 1


async def test_an_async_is_connected_is_not_reported_when_redis_fails_closed(
    handler: RecordingRedisHandler,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.setattr(handler, "is_connected", async_false)
    config = handler.config.model_copy(
        update={"redis_fail_open": False, "fail_on_misconfiguration": True}
    )
    with caplog.at_level(logging.WARNING):
        await HandlerInitializer(
            config, redis_handler=handler
        ).initialize_redis_handlers()
    assert not [r for r in caplog.records if "without awaiting" in r.getMessage()]
