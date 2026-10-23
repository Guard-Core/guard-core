from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.handlers.cloud_ip_stores import RedisCloudIpStore


@pytest.fixture
def redis_handler() -> MagicMock:
    handler = MagicMock()
    handler.config = MagicMock(redis_prefix="test:")
    handler.initialize = MagicMock()
    return handler


def test_instance_form_passed_to_set_store(redis_handler: MagicMock) -> None:
    instance = RedisCloudIpStore(redis_handler, key_prefix="custom")
    config = SyncSecurityConfig(enable_redis=True, cloud_ip_store=instance)

    from guard_core.sync.core.initialization.handler_initializer import (
        HandlerInitializer,
    )

    init = HandlerInitializer(config=config, redis_handler=redis_handler)

    with (
        patch(
            "guard_core.sync.handlers.cloud_handler.cloud_handler.set_store"
        ) as mock_set,
        patch(
            "guard_core.sync.handlers.ipban_handler.ip_ban_manager.initialize_redis",
        ),
        patch(
            "guard_core.sync.handlers.suspatterns_handler.sus_patterns_handler.initialize_redis",
        ),
    ):
        init.initialize_redis_handlers()

    mock_set.assert_called_once_with(instance)


def test_callable_form_invoked_with_redis_handler(
    redis_handler: MagicMock,
) -> None:
    factory_calls: list[Any] = []

    def factory(redis: Any) -> RedisCloudIpStore:
        factory_calls.append(redis)
        return RedisCloudIpStore(redis, key_prefix="from_factory")

    config = SyncSecurityConfig(enable_redis=True, cloud_ip_store=factory)

    from guard_core.sync.core.initialization.handler_initializer import (
        HandlerInitializer,
    )

    init = HandlerInitializer(config=config, redis_handler=redis_handler)

    with (
        patch(
            "guard_core.sync.handlers.cloud_handler.cloud_handler.set_store"
        ) as mock_set,
        patch(
            "guard_core.sync.handlers.ipban_handler.ip_ban_manager.initialize_redis",
        ),
        patch(
            "guard_core.sync.handlers.suspatterns_handler.sus_patterns_handler.initialize_redis",
        ),
    ):
        init.initialize_redis_handlers()

    assert factory_calls == [redis_handler]
    mock_set.assert_called_once()
    args, _ = mock_set.call_args
    assert isinstance(args[0], RedisCloudIpStore)
    assert args[0]._prefix == "from_factory"


def test_class_object_passed_as_factory_is_invoked(
    redis_handler: MagicMock,
) -> None:
    config = SyncSecurityConfig(enable_redis=True, cloud_ip_store=RedisCloudIpStore)

    from guard_core.sync.core.initialization.handler_initializer import (
        HandlerInitializer,
    )

    init = HandlerInitializer(config=config, redis_handler=redis_handler)

    with (
        patch(
            "guard_core.sync.handlers.cloud_handler.cloud_handler.set_store"
        ) as mock_set,
        patch(
            "guard_core.sync.handlers.ipban_handler.ip_ban_manager.initialize_redis",
        ),
        patch(
            "guard_core.sync.handlers.suspatterns_handler.sus_patterns_handler.initialize_redis",
        ),
    ):
        init.initialize_redis_handlers()

    mock_set.assert_called_once()
    args, _ = mock_set.call_args
    assert isinstance(args[0], RedisCloudIpStore)


def test_callable_form_invoked_on_no_redis_path() -> None:
    factory_calls: list[Any] = []

    def factory(redis: Any) -> RedisCloudIpStore:
        factory_calls.append(redis)
        return RedisCloudIpStore(redis, key_prefix="no_redis_path")

    config = SyncSecurityConfig(
        enable_redis=False, lazy_init=False, cloud_ip_store=factory
    )

    from guard_core.sync.core.initialization.handler_initializer import (
        HandlerInitializer,
    )

    init = HandlerInitializer(config=config, redis_handler=None)

    with patch(
        "guard_core.sync.handlers.cloud_handler.cloud_handler.set_store"
    ) as mock_set:
        init.initialize_redis_handlers()

    assert factory_calls == [None]
    mock_set.assert_called_once()
    args, _ = mock_set.call_args
    assert isinstance(args[0], RedisCloudIpStore)
    assert args[0]._prefix == "no_redis_path"


def test_none_does_not_call_set_store(redis_handler: MagicMock) -> None:
    config = SyncSecurityConfig(enable_redis=True, cloud_ip_store=None)

    from guard_core.sync.core.initialization.handler_initializer import (
        HandlerInitializer,
    )

    init = HandlerInitializer(config=config, redis_handler=redis_handler)

    with (
        patch(
            "guard_core.sync.handlers.cloud_handler.cloud_handler.set_store"
        ) as mock_set,
        patch(
            "guard_core.sync.handlers.ipban_handler.ip_ban_manager.initialize_redis",
        ),
        patch(
            "guard_core.sync.handlers.suspatterns_handler.sus_patterns_handler.initialize_redis",
        ),
    ):
        init.initialize_redis_handlers()

    mock_set.assert_not_called()
