from collections.abc import Iterator
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from guard_core.models import SecurityConfig, SyncSecurityConfig
from guard_core.sync.handlers import ipban_handler as sync_ipban_module
from guard_core.sync.handlers import suspatterns_handler as sync_suspatterns_module

_SYNC_DEFAULTS = (
    (
        sync_suspatterns_module.sus_patterns_handler,
        ("_detection_state",),
    ),
    (
        sync_suspatterns_module.SusPatternsManager,
        (
            "_config",
            "_sensitive_headers_union",
            "_sensitive_params_union",
            "_sensitive_body_fields_union",
        ),
    ),
    (sync_ipban_module.ip_ban_manager, ("config",)),
)


def _sync_default_state() -> list[object]:
    return [getattr(owner, name) for owner, names in _SYNC_DEFAULTS for name in names]


_PRISTINE_SYNC_DEFAULTS = _sync_default_state()


@pytest.fixture(autouse=True)
def _restore_sync_defaults() -> Iterator[None]:
    # tests/test_sync/conftest.py resets these only for the sync tree, and
    # tests/conftest.py only for the async tree, so a sync initializer run from
    # this file has to put back what it configures
    saved = _sync_default_state()
    yield
    values = iter(saved)
    for owner, names in _SYNC_DEFAULTS:
        for name in names:
            setattr(owner, name, next(values))


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


def test_sync_initializer_run_leaves_sync_defaults_untouched() -> None:
    assert _sync_default_state() == _PRISTINE_SYNC_DEFAULTS
