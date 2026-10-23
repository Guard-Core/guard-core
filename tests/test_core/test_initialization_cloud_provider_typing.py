from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from guard_core.models import SecurityConfig, SyncSecurityConfig


@pytest.mark.asyncio
async def test_async_initializer_passes_set_str_to_cloud_handler() -> None:
    config = SecurityConfig(
        enable_redis=True,
        lazy_init=False,
        block_cloud_providers={"AWS", "GCP"},
    )

    redis_handler = MagicMock()
    redis_handler.initialize = AsyncMock()
    redis_handler.config = config

    from guard_core.core.initialization.handler_initializer import (
        HandlerInitializer,
    )

    init = HandlerInitializer(config=config, redis_handler=redis_handler)

    with (
        patch(
            "guard_core.handlers.cloud_handler.cloud_handler.initialize_redis",
            new_callable=AsyncMock,
        ) as mock_init,
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

    assert mock_init.await_count == 1
    args, kwargs = mock_init.call_args
    providers_arg = args[1] if len(args) > 1 else kwargs["providers"]
    assert providers_arg == {"AWS", "GCP"}


def test_sync_initializer_passes_set_str_to_cloud_handler() -> None:
    config = SyncSecurityConfig(
        enable_redis=True,
        block_cloud_providers={"AWS", "GCP"},
    )

    redis_handler = MagicMock()
    redis_handler.config = config

    from guard_core.sync.core.initialization.handler_initializer import (
        HandlerInitializer,
    )

    init = HandlerInitializer(config=config, redis_handler=redis_handler)

    with (
        patch(
            "guard_core.sync.handlers.cloud_handler.cloud_handler.initialize_redis"
        ) as mock_init,
        patch("guard_core.sync.handlers.ipban_handler.ip_ban_manager.initialize_redis"),
        patch(
            "guard_core.sync.handlers.suspatterns_handler.sus_patterns_handler.initialize_redis"
        ),
    ):
        init.initialize_redis_handlers()

    assert mock_init.call_count == 1
    args, kwargs = mock_init.call_args
    providers_arg = args[1] if len(args) > 1 else kwargs["providers"]
    assert providers_arg == {"AWS", "GCP"}
