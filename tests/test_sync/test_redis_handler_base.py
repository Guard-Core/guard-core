import logging
import time
from collections.abc import Generator, Iterator
from contextlib import contextmanager
from typing import Protocol, runtime_checkable

import pytest
from redis import Redis

from guard_core.models import SyncSecurityConfig
from guard_core.sync.core.initialization._redis_handler_members import (
    missing_redis_handler_members,
)
from guard_core.sync.core.initialization.handler_initializer import HandlerInitializer
from guard_core.sync.handlers.redis_handler import (
    RedisHandlerBase,
    RedisManager,
    close_redis_client,
)
from guard_core.sync.protocols.redis_protocol import SyncRedisHandlerProtocol
from tests.test_sync.conftest import suite_redis_prefix
from tests.test_sync.protocol_only_redis import REDIS_URL, protocol_only_handler

IP = "198.51.100.77"


@runtime_checkable
class RecordingRedisHandler(SyncRedisHandlerProtocol, Protocol):
    used: set[str]


@pytest.fixture
def handler() -> Generator[RecordingRedisHandler, None]:
    with protocol_only_handler() as fake:
        assert isinstance(fake, RecordingRedisHandler)
        yield fake


def test_a_handler_missing_methods_is_named_at_startup(
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
        initializer.initialize_redis_handlers()
    named = [r.getMessage() for r in caplog.records if "lacks" in r.getMessage()]
    assert len(named) == 1
    assert "owned_ban_state, write_atomically" in named[0]


def test_a_handler_missing_one_method_refuses_to_start_when_asked(
    handler: RecordingRedisHandler,
) -> None:
    del handler.disown_ban
    config = handler.config.model_copy(update={"fail_on_misconfiguration": True})
    initializer = HandlerInitializer(config, redis_handler=handler)
    with pytest.raises(ValueError, match="lacks disown_ban,? "):
        initializer.initialize_redis_handlers()


def test_the_redis_manager_and_the_base_pass_the_startup_check(
    handler: RecordingRedisHandler,
) -> None:
    assert missing_redis_handler_members(RedisManager(handler.config)) == []
    assert isinstance(RedisManager(handler.config), SyncRedisHandlerProtocol)


class _OwnPoolHandler(RedisHandlerBase):
    def __init__(self, config: SyncSecurityConfig) -> None:
        self.config = config
        self._client: Redis | None = None

    def initialize(self) -> None:
        self._client = Redis.from_url(REDIS_URL, decode_responses=True)

    @contextmanager
    def get_connection(self) -> Iterator[Redis]:
        assert self._client is not None
        yield self._client

    def close(self) -> None:
        assert self._client is not None
        close_redis_client(self._client)


def test_a_subclass_of_the_base_gets_every_default() -> None:
    config = SyncSecurityConfig(
        enable_redis=True,
        redis_url=REDIS_URL,
        redis_prefix=suite_redis_prefix("wp69base"),
    )
    own = _OwnPoolHandler(config)
    assert missing_redis_handler_members(own) == []
    own.initialize()
    try:
        assert own.set_key("ns", "k", "v")
        assert own.get_key("ns", "k") == "v"
        assert own.get_many([("ns", "k"), ("ns", "none")]) == ["v", None]
        assert own.set_key_if_absent("ns", "k", "w") is False
        assert own.incr("ns", "n") == 1
        now = time.time()
        assert own.record_sliding_window_hit("w", "k", now, now - 60, 60) == 1
        assert own.count_sliding_window_hits("w", "k", now - 60) == 1
        assert own.write_ban_extending_only(
            "banned_ips", IP, str(now + 60), 60, version=("v", "c")
        ) == pytest.approx(now + 60)
        assert own.delete_pattern("*") == 4
    finally:
        own.close()


def test_the_base_reuses_the_managers_own_implementation() -> None:
    for name in ("record_sliding_window_hit", "write_ban_extending_only", "get_many"):
        assert getattr(RedisHandlerBase, name) is getattr(RedisManager, name)


def test_a_subclass_of_the_base_is_not_the_manager_singleton() -> None:
    config = SyncSecurityConfig(enable_redis=True, redis_url=REDIS_URL)
    first, second = _OwnPoolHandler(config), _OwnPoolHandler(config)
    assert first is not second
    assert first is not RedisManager(config)


def _singleton() -> object:
    return RedisManager._instance


def reset_singleton() -> None:
    RedisManager._instance = None


def test_a_base_subclass_leaves_the_manager_singleton_alone() -> None:
    # D-112 item 1: RedisManager._instance stays the most recently constructed
    # and initialized RedisManager; a RedisHandlerBase subclass is never it.
    config = SyncSecurityConfig(
        enable_redis=True,
        redis_url=REDIS_URL,
        redis_prefix=suite_redis_prefix("wp69inst"),
    )
    reset_singleton()
    own = _OwnPoolHandler(config)
    own.initialize()
    try:
        assert _singleton() is None
        manager = RedisManager(config)
        assert _singleton() is manager
        assert manager is not own
        inherited = RedisHandlerBase(config)
        inherited.initialize()
        try:
            assert _singleton() is manager
            assert RedisManager(config) is manager
            assert inherited is not manager
        finally:
            inherited.close()
    finally:
        own.close()
        reset_singleton()
