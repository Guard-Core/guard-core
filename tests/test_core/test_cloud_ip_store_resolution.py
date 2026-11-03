from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from guard_core.handlers.cloud_ip_stores import RedisCloudIpStore
from guard_core.models import SecurityConfig
from guard_core.protocols.redis_protocol import RedisHandlerProtocol


@pytest.fixture
def redis_handler() -> MagicMock:
    handler = MagicMock()
    handler.config = MagicMock(redis_prefix="test:")
    handler.initialize = AsyncMock()
    return handler


@pytest.mark.asyncio
async def test_instance_form_passed_to_set_store(redis_handler: MagicMock) -> None:
    instance = RedisCloudIpStore(redis_handler, key_prefix="custom")
    config = SecurityConfig(enable_redis=True, cloud_ip_store=instance)

    from guard_core.core.initialization.handler_initializer import (
        HandlerInitializer,
    )

    init = HandlerInitializer(config=config, redis_handler=redis_handler)

    with (
        patch("guard_core.handlers.cloud_handler.cloud_handler.set_store") as mock_set,
        patch(
            "guard_core.handlers.ipban_handler.ip_ban_manager.initialize_redis",
            new_callable=AsyncMock,
        ),
        patch(
            "guard_core.handlers.suspatterns_handler.sus_patterns_handler.initialize_redis",
            new_callable=AsyncMock,
        ),
    ):
        await init.initialize_redis_handlers()

    mock_set.assert_called_once_with(instance)


@pytest.mark.asyncio
async def test_callable_form_invoked_with_redis_handler(
    redis_handler: MagicMock,
) -> None:
    factory_calls: list[Any] = []

    def factory(redis: RedisHandlerProtocol) -> RedisCloudIpStore:
        factory_calls.append(redis)
        return RedisCloudIpStore(redis, key_prefix="from_factory")

    config = SecurityConfig(enable_redis=True, cloud_ip_store=factory)

    from guard_core.core.initialization.handler_initializer import (
        HandlerInitializer,
    )

    init = HandlerInitializer(config=config, redis_handler=redis_handler)

    with (
        patch("guard_core.handlers.cloud_handler.cloud_handler.set_store") as mock_set,
        patch(
            "guard_core.handlers.ipban_handler.ip_ban_manager.initialize_redis",
            new_callable=AsyncMock,
        ),
        patch(
            "guard_core.handlers.suspatterns_handler.sus_patterns_handler.initialize_redis",
            new_callable=AsyncMock,
        ),
    ):
        await init.initialize_redis_handlers()

    assert factory_calls == [redis_handler]
    mock_set.assert_called_once()
    args, _ = mock_set.call_args
    assert isinstance(args[0], RedisCloudIpStore)
    assert args[0]._prefix == "from_factory"


@pytest.mark.asyncio
async def test_class_object_passed_as_factory_is_invoked(
    redis_handler: MagicMock,
) -> None:
    config = SecurityConfig(enable_redis=True, cloud_ip_store=RedisCloudIpStore)

    from guard_core.core.initialization.handler_initializer import (
        HandlerInitializer,
    )

    init = HandlerInitializer(config=config, redis_handler=redis_handler)

    with (
        patch("guard_core.handlers.cloud_handler.cloud_handler.set_store") as mock_set,
        patch(
            "guard_core.handlers.ipban_handler.ip_ban_manager.initialize_redis",
            new_callable=AsyncMock,
        ),
        patch(
            "guard_core.handlers.suspatterns_handler.sus_patterns_handler.initialize_redis",
            new_callable=AsyncMock,
        ),
    ):
        await init.initialize_redis_handlers()

    mock_set.assert_called_once()
    args, _ = mock_set.call_args
    assert isinstance(args[0], RedisCloudIpStore)


@pytest.mark.asyncio
async def test_callable_form_invoked_on_no_redis_path() -> None:
    factory_calls: list[Any] = []

    def factory(redis: RedisHandlerProtocol) -> RedisCloudIpStore:
        factory_calls.append(redis)
        return RedisCloudIpStore(redis, key_prefix="no_redis_path")

    config = SecurityConfig(enable_redis=False, lazy_init=False, cloud_ip_store=factory)

    from guard_core.core.initialization.handler_initializer import (
        HandlerInitializer,
    )

    init = HandlerInitializer(config=config, redis_handler=None)

    with patch("guard_core.handlers.cloud_handler.cloud_handler.set_store") as mock_set:
        await init.initialize_redis_handlers()

    assert factory_calls == [None]
    mock_set.assert_called_once()
    args, _ = mock_set.call_args
    assert isinstance(args[0], RedisCloudIpStore)
    assert args[0]._prefix == "no_redis_path"


async def test_none_does_not_call_set_store(redis_handler: MagicMock) -> None:
    config = SecurityConfig(enable_redis=True, cloud_ip_store=None)

    from guard_core.core.initialization.handler_initializer import (
        HandlerInitializer,
    )

    init = HandlerInitializer(config=config, redis_handler=redis_handler)

    with (
        patch("guard_core.handlers.cloud_handler.cloud_handler.set_store") as mock_set,
        patch(
            "guard_core.handlers.ipban_handler.ip_ban_manager.initialize_redis",
            new_callable=AsyncMock,
        ),
        patch(
            "guard_core.handlers.suspatterns_handler.sus_patterns_handler.initialize_redis",
            new_callable=AsyncMock,
        ),
    ):
        await init.initialize_redis_handlers()

    mock_set.assert_not_called()
