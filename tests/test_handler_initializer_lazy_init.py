import asyncio
import threading
import time
from contextlib import contextmanager
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

from guard_core.core.initialization.handler_initializer import HandlerInitializer
from guard_core.models import SecurityConfig


def _make_initializer(
    lazy_init: bool, block_cloud: set[str] | None = None
) -> tuple[HandlerInitializer, MagicMock, MagicMock]:
    config = SecurityConfig(
        lazy_init=lazy_init,
        enable_redis=True,
        block_cloud_providers=block_cloud or set(),
    )
    redis_handler = MagicMock()
    redis_handler.initialize = AsyncMock()
    redis_handler.initialize_agent = AsyncMock()
    geo_ip = MagicMock()
    geo_ip.initialize_redis = AsyncMock()
    rate_limit = MagicMock()
    rate_limit.initialize_redis = AsyncMock()
    return (
        HandlerInitializer(
            config=config,
            redis_handler=redis_handler,
            geo_ip_handler=geo_ip,
            rate_limit_handler=rate_limit,
        ),
        geo_ip,
        redis_handler,
    )


@contextmanager
def _patch_handlers() -> Any:
    with (
        patch("guard_core.handlers.cloud_handler.cloud_handler") as cloud,
        patch("guard_core.handlers.ipban_handler.ip_ban_manager") as ipban,
        patch("guard_core.handlers.suspatterns_handler.sus_patterns_handler") as sus,
    ):
        cloud.initialize_redis = AsyncMock()
        cloud.refresh = AsyncMock()
        cloud.set_store = MagicMock()
        ipban.initialize_redis = AsyncMock()
        sus.initialize_redis = AsyncMock()
        yield {"cloud": cloud, "ipban": ipban, "suspatterns": sus}


async def test_eager_init_runs_geo_and_cloud() -> None:
    initializer, geo_ip, _ = _make_initializer(lazy_init=False, block_cloud={"AWS"})
    with _patch_handlers() as patches:
        await initializer.initialize_redis_handlers()
        patches["cloud"].initialize_redis.assert_awaited_once()
    geo_ip.initialize_redis.assert_awaited_once()


async def test_lazy_init_schedules_background_task_for_cloud_and_geo() -> None:
    initializer, geo_ip, _ = _make_initializer(lazy_init=True, block_cloud={"AWS"})
    with _patch_handlers() as patches:
        await initializer.initialize_redis_handlers()
        assert initializer._lazy_init_task is not None
        await asyncio.wait_for(initializer._lazy_init_task, timeout=1.0)
        patches["cloud"].initialize_redis.assert_awaited_once()
    geo_ip.initialize_redis.assert_awaited_once()


async def test_lazy_init_returns_fast_with_slow_background() -> None:  # async-only
    initializer, geo_ip, _ = _make_initializer(lazy_init=True, block_cloud={"AWS"})

    async def slow_cloud_init(*args: Any, **kwargs: Any) -> None:
        await asyncio.sleep(5)

    async def slow_geo_init(*args: Any, **kwargs: Any) -> None:
        await asyncio.sleep(5)

    geo_ip.initialize_redis = AsyncMock(side_effect=slow_geo_init)

    with _patch_handlers() as patches:
        patches["cloud"].initialize_redis = AsyncMock(side_effect=slow_cloud_init)
        start = time.perf_counter()
        await initializer.initialize_redis_handlers()
        elapsed = time.perf_counter() - start

        # Load headroom: the contract is "returns without waiting for the
        # background init", not a wall-clock budget - a saturated CI runner
        # measured 0.54s against the old 0.5s bound (ledger F5). 5s still
        # fails loudly if lazy init ever blocks on the background work.
        assert elapsed < 5.0
        assert initializer._lazy_init_task is not None
        assert initializer._lazy_init_task.done() is False
        initializer._lazy_init_task.cancel()
        try:
            await initializer._lazy_init_task
        except asyncio.CancelledError:
            pass


async def test_lazy_init_returns_quickly_with_blocking_background_init() -> None:
    initializer, geo_ip, _ = _make_initializer(lazy_init=True, block_cloud={"AWS"})

    release = threading.Event()

    async def blocking_cloud_init(*args: Any, **kwargs: Any) -> None:
        release.set()

    geo_ip.initialize_redis = AsyncMock(side_effect=blocking_cloud_init)

    with _patch_handlers() as patches:
        patches["cloud"].initialize_redis = AsyncMock(side_effect=blocking_cloud_init)
        start = time.perf_counter()
        await initializer.initialize_redis_handlers()
        elapsed = time.perf_counter() - start

        assert elapsed < 0.5
        assert initializer._lazy_init_task is not None
        await asyncio.wait_for(initializer._lazy_init_task, timeout=1.0)


async def test_lazy_init_cloud_failure_still_runs_geo_init() -> None:
    initializer, geo_ip, _ = _make_initializer(lazy_init=True, block_cloud={"AWS"})
    geo_ip.initialize_redis = AsyncMock()

    with _patch_handlers() as patches:
        patches["cloud"].initialize_redis = AsyncMock(
            side_effect=RuntimeError("AWS API down")
        )
        with patch.object(initializer.logger, "warning") as mock_warning:
            await initializer.initialize_redis_handlers()
            assert initializer._lazy_init_task is not None
            await asyncio.wait_for(initializer._lazy_init_task, timeout=1.0)
            mock_warning.assert_called_once()
            assert "cloud-IP" in mock_warning.call_args[0][0]
            geo_ip.initialize_redis.assert_awaited_once()


async def test_lazy_init_geo_failure_does_not_break_cloud_init() -> None:
    initializer, geo_ip, _ = _make_initializer(lazy_init=True, block_cloud={"AWS"})
    geo_ip.initialize_redis = AsyncMock(side_effect=RuntimeError("geo down"))

    with _patch_handlers() as patches:
        patches["cloud"].initialize_redis = AsyncMock()
        with patch.object(initializer.logger, "warning") as mock_warning:
            await initializer.initialize_redis_handlers()
            assert initializer._lazy_init_task is not None
            await asyncio.wait_for(initializer._lazy_init_task, timeout=1.0)
            patches["cloud"].initialize_redis.assert_awaited_once()
            mock_warning.assert_called_once()
            assert "geo-IP" in mock_warning.call_args[0][0]


async def test_lazy_init_background_task_runs_geo_only_when_no_cloud_providers() -> (
    None
):
    initializer, geo_ip, _ = _make_initializer(lazy_init=True, block_cloud=None)
    with _patch_handlers() as patches:
        await initializer.initialize_redis_handlers()
        assert initializer._lazy_init_task is not None
        await asyncio.wait_for(initializer._lazy_init_task, timeout=1.0)
        patches["cloud"].initialize_redis.assert_not_awaited()
    geo_ip.initialize_redis.assert_awaited_once()


async def test_lazy_init_background_task_runs_cloud_only_when_no_geo_handler() -> None:
    config = SecurityConfig(
        lazy_init=True,
        enable_redis=True,
        block_cloud_providers={"AWS"},
    )
    redis_handler = MagicMock()
    redis_handler.initialize = AsyncMock()
    initializer = HandlerInitializer(
        config=config,
        redis_handler=redis_handler,
        geo_ip_handler=None,
    )
    with _patch_handlers() as patches:
        await initializer.initialize_redis_handlers()
        assert initializer._lazy_init_task is not None
        await asyncio.wait_for(initializer._lazy_init_task, timeout=1.0)
        patches["cloud"].initialize_redis.assert_awaited_once()


async def test_lazy_init_still_initializes_ipban_and_suspatterns() -> None:
    initializer, _, _ = _make_initializer(lazy_init=True)
    with _patch_handlers() as patches:
        await initializer.initialize_redis_handlers()
        if initializer._lazy_init_task is not None:
            await asyncio.wait_for(initializer._lazy_init_task, timeout=1.0)
        patches["ipban"].initialize_redis.assert_awaited_once()
        patches["suspatterns"].initialize_redis.assert_awaited_once()


async def test_lazy_init_with_empty_cloud_providers_skips_cloud() -> None:
    initializer, _, _ = _make_initializer(lazy_init=False, block_cloud=None)
    with _patch_handlers() as patches:
        await initializer.initialize_redis_handlers()
        patches["cloud"].initialize_redis.assert_not_awaited()


async def test_no_redis_handler_returns_immediately() -> None:
    config = SecurityConfig(lazy_init=False, enable_redis=True)
    initializer = HandlerInitializer(config=config, redis_handler=None)
    await initializer.initialize_redis_handlers()


async def test_warns_when_lazy_init_inert_without_redis_and_cloud_configured() -> None:
    config = SecurityConfig(lazy_init=True, block_cloud_providers={"AWS"})
    initializer = HandlerInitializer(config=config, redis_handler=None)

    with patch.object(initializer.logger, "warning") as mock_warning:
        await initializer.initialize_redis_handlers()

    mock_warning.assert_called_once()
    assert "lazy_init has no effect" in mock_warning.call_args[0][0]


async def test_warns_when_lazy_init_inert_with_geo_ip_handler_configured() -> None:
    config = SecurityConfig(lazy_init=True)
    geo_ip = MagicMock()
    initializer = HandlerInitializer(
        config=config, redis_handler=None, geo_ip_handler=geo_ip
    )

    with patch.object(initializer.logger, "warning") as mock_warning:
        await initializer.initialize_redis_handlers()

    mock_warning.assert_called_once()
    assert "lazy_init has no effect" in mock_warning.call_args[0][0]


async def test_no_warning_when_lazy_init_false_and_geo_ip_handler_configured() -> None:
    config = SecurityConfig(lazy_init=False)
    geo_ip = MagicMock()
    geo_ip.initialize = AsyncMock()
    initializer = HandlerInitializer(
        config=config, redis_handler=None, geo_ip_handler=geo_ip
    )

    with patch.object(initializer.logger, "warning") as mock_warning:
        await initializer.initialize_redis_handlers()

    mock_warning.assert_not_called()


async def test_no_warning_when_lazy_init_inert_but_nothing_configured() -> None:
    config = SecurityConfig(lazy_init=True)
    initializer = HandlerInitializer(config=config, redis_handler=None)

    with patch.object(initializer.logger, "warning") as mock_warning:
        await initializer.initialize_redis_handlers()

    mock_warning.assert_not_called()


async def test_no_redis_eager_loads_cloud_when_lazy_init_false() -> None:
    config = SecurityConfig(
        lazy_init=False,
        enable_redis=False,
        block_cloud_providers={"AWS"},
    )
    geo_ip = MagicMock()
    geo_ip.initialize = AsyncMock()
    geo_ip.initialize_redis = AsyncMock()
    initializer = HandlerInitializer(
        config=config, redis_handler=None, geo_ip_handler=geo_ip
    )

    with _patch_handlers() as patches:
        await initializer.initialize_redis_handlers()
        patches["cloud"].refresh.assert_awaited_once_with({"AWS"})
        patches["cloud"].initialize_redis.assert_not_awaited()

    geo_ip.initialize.assert_awaited_once()
    geo_ip.initialize_redis.assert_not_awaited()


async def test_no_redis_eager_load_skips_cloud_when_no_providers() -> None:
    config = SecurityConfig(
        lazy_init=False,
        enable_redis=False,
        block_cloud_providers=set(),
    )
    geo_ip = MagicMock()
    geo_ip.initialize = AsyncMock()
    initializer = HandlerInitializer(
        config=config, redis_handler=None, geo_ip_handler=geo_ip
    )

    with _patch_handlers() as patches:
        await initializer.initialize_redis_handlers()
        patches["cloud"].refresh.assert_not_awaited()

    geo_ip.initialize.assert_awaited_once()


async def test_no_redis_eager_load_skips_geo_when_no_geo_handler() -> None:
    config = SecurityConfig(
        lazy_init=False,
        enable_redis=False,
        block_cloud_providers={"AWS"},
    )
    initializer = HandlerInitializer(
        config=config, redis_handler=None, geo_ip_handler=None
    )

    with _patch_handlers() as patches:
        await initializer.initialize_redis_handlers()
        patches["cloud"].refresh.assert_awaited_once_with({"AWS"})


async def test_no_redis_lazy_init_true_does_not_eager_load_cloud() -> None:
    config = SecurityConfig(
        lazy_init=True,
        enable_redis=False,
        block_cloud_providers={"AWS"},
    )
    geo_ip = MagicMock()
    geo_ip.initialize = AsyncMock()
    initializer = HandlerInitializer(
        config=config, redis_handler=None, geo_ip_handler=geo_ip
    )

    with _patch_handlers() as patches:
        with patch.object(initializer.logger, "warning") as mock_warning:
            await initializer.initialize_redis_handlers()
            patches["cloud"].refresh.assert_not_awaited()
            geo_ip.initialize.assert_not_awaited()
            mock_warning.assert_called_once()
