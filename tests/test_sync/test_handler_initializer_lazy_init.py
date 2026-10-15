import time
from contextlib import contextmanager
from typing import Any
from unittest.mock import MagicMock, patch

from guard_core.models import SecurityConfig
from guard_core.sync.core.initialization.handler_initializer import HandlerInitializer

_BACKGROUND_BLOCK_SECONDS = 2.0


def _make_initializer(
    lazy_init: bool, block_cloud: set[str] | None = None
) -> tuple[HandlerInitializer, MagicMock, MagicMock]:
    config = SecurityConfig(
        lazy_init=lazy_init,
        enable_redis=True,
        block_cloud_providers=block_cloud or set(),
    )
    redis_handler = MagicMock()
    redis_handler.initialize = MagicMock()
    redis_handler.initialize_agent = MagicMock()
    geo_ip = MagicMock()
    geo_ip.initialize_redis = MagicMock()
    rate_limit = MagicMock()
    rate_limit.initialize_redis = MagicMock()
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
        patch("guard_core.sync.handlers.cloud_handler.cloud_handler") as cloud,
        patch("guard_core.sync.handlers.ipban_handler.ip_ban_manager") as ipban,
        patch(
            "guard_core.sync.handlers.suspatterns_handler.sus_patterns_handler"
        ) as sus,
    ):
        cloud.initialize_redis = MagicMock()
        cloud.refresh = MagicMock()
        cloud.set_store = MagicMock()
        ipban.initialize_redis = MagicMock()
        sus.initialize_redis = MagicMock()
        yield {"cloud": cloud, "ipban": ipban, "suspatterns": sus}


def test_eager_init_runs_geo_and_cloud() -> None:
    initializer, geo_ip, _ = _make_initializer(lazy_init=False, block_cloud={"AWS"})
    with _patch_handlers() as patches:
        initializer.initialize_redis_handlers()
        patches["cloud"].initialize_redis.assert_called_once()
    geo_ip.initialize_redis.assert_called_once()


def test_lazy_init_schedules_background_task_for_cloud_and_geo() -> None:
    initializer, geo_ip, _ = _make_initializer(lazy_init=True, block_cloud={"AWS"})
    with _patch_handlers() as patches:
        initializer.initialize_redis_handlers()
        assert initializer._lazy_init_task is not None
        initializer._lazy_init_task.join(timeout=1.0)
        patches["cloud"].initialize_redis.assert_called_once()
    geo_ip.initialize_redis.assert_called_once()


def test_lazy_init_returns_quickly_with_blocking_background_init() -> None:
    initializer, geo_ip, _ = _make_initializer(lazy_init=True, block_cloud={"AWS"})

    finished: list[str] = []

    def blocking_cloud_init(*args: Any, **kwargs: Any) -> None:
        time.sleep(_BACKGROUND_BLOCK_SECONDS)
        finished.append("cloud")

    geo_ip.initialize_redis = MagicMock()

    with _patch_handlers() as patches:
        patches["cloud"].initialize_redis = MagicMock(side_effect=blocking_cloud_init)
        initializer.initialize_redis_handlers()

        # The contract is "returns without waiting for the background init",
        # asserted as ordering rather than a wall-clock budget: the background
        # init is still inside its block when the call returns. A lazy init
        # that awaited it would have finished it first, however fast the
        # runner is (the old 0.5s bound flaked at 0.56-0.69s under load, and
        # could not fail on a real regression because the stub never blocked).
        assert initializer._lazy_init_task is not None
        assert finished == []
        initializer._lazy_init_task.join(timeout=30.0)
        assert finished == ["cloud"]
        geo_ip.initialize_redis.assert_called_once()


def test_lazy_init_cloud_failure_still_runs_geo_init() -> None:
    initializer, geo_ip, _ = _make_initializer(lazy_init=True, block_cloud={"AWS"})
    geo_ip.initialize_redis = MagicMock()

    with _patch_handlers() as patches:
        patches["cloud"].initialize_redis = MagicMock(
            side_effect=RuntimeError("AWS API down")
        )
        with patch.object(initializer.logger, "warning") as mock_warning:
            initializer.initialize_redis_handlers()
            assert initializer._lazy_init_task is not None
            initializer._lazy_init_task.join(timeout=1.0)
            mock_warning.assert_called_once()
            assert "cloud-IP" in mock_warning.call_args[0][0]
            geo_ip.initialize_redis.assert_called_once()


def test_lazy_init_geo_failure_does_not_break_cloud_init() -> None:
    initializer, geo_ip, _ = _make_initializer(lazy_init=True, block_cloud={"AWS"})
    geo_ip.initialize_redis = MagicMock(side_effect=RuntimeError("geo down"))

    with _patch_handlers() as patches:
        patches["cloud"].initialize_redis = MagicMock()
        with patch.object(initializer.logger, "warning") as mock_warning:
            initializer.initialize_redis_handlers()
            assert initializer._lazy_init_task is not None
            initializer._lazy_init_task.join(timeout=1.0)
            patches["cloud"].initialize_redis.assert_called_once()
            mock_warning.assert_called_once()
            assert "geo-IP" in mock_warning.call_args[0][0]


def test_lazy_init_background_task_runs_geo_only_when_no_cloud_providers() -> None:
    initializer, geo_ip, _ = _make_initializer(lazy_init=True, block_cloud=None)
    with _patch_handlers() as patches:
        initializer.initialize_redis_handlers()
        assert initializer._lazy_init_task is not None
        initializer._lazy_init_task.join(timeout=1.0)
        patches["cloud"].initialize_redis.assert_not_called()
    geo_ip.initialize_redis.assert_called_once()


def test_lazy_init_background_task_runs_cloud_only_when_no_geo_handler() -> None:
    config = SecurityConfig(
        lazy_init=True,
        enable_redis=True,
        block_cloud_providers={"AWS"},
    )
    redis_handler = MagicMock()
    redis_handler.initialize = MagicMock()
    initializer = HandlerInitializer(
        config=config,
        redis_handler=redis_handler,
        geo_ip_handler=None,
    )
    with _patch_handlers() as patches:
        initializer.initialize_redis_handlers()
        assert initializer._lazy_init_task is not None
        initializer._lazy_init_task.join(timeout=1.0)
        patches["cloud"].initialize_redis.assert_called_once()


def test_lazy_init_still_initializes_ipban_and_suspatterns() -> None:
    initializer, _, _ = _make_initializer(lazy_init=True)
    with _patch_handlers() as patches:
        initializer.initialize_redis_handlers()
        if initializer._lazy_init_task is not None:
            initializer._lazy_init_task.join(timeout=1.0)
        patches["ipban"].initialize_redis.assert_called_once()
        patches["suspatterns"].initialize_redis.assert_called_once()


def test_lazy_init_with_empty_cloud_providers_skips_cloud() -> None:
    initializer, _, _ = _make_initializer(lazy_init=False, block_cloud=None)
    with _patch_handlers() as patches:
        initializer.initialize_redis_handlers()
        patches["cloud"].initialize_redis.assert_not_called()


def test_no_redis_handler_returns_immediately() -> None:
    config = SecurityConfig(lazy_init=False, enable_redis=True)
    initializer = HandlerInitializer(config=config, redis_handler=None)
    initializer.initialize_redis_handlers()


def test_warns_when_lazy_init_inert_without_redis_and_cloud_configured() -> None:
    config = SecurityConfig(lazy_init=True, block_cloud_providers={"AWS"})
    initializer = HandlerInitializer(config=config, redis_handler=None)

    with patch.object(initializer.logger, "warning") as mock_warning:
        initializer.initialize_redis_handlers()

    mock_warning.assert_called_once()
    assert "lazy_init has no effect" in mock_warning.call_args[0][0]


def test_warns_when_lazy_init_inert_with_geo_ip_handler_configured() -> None:
    config = SecurityConfig(lazy_init=True)
    geo_ip = MagicMock()
    initializer = HandlerInitializer(
        config=config, redis_handler=None, geo_ip_handler=geo_ip
    )

    with patch.object(initializer.logger, "warning") as mock_warning:
        initializer.initialize_redis_handlers()

    mock_warning.assert_called_once()
    assert "lazy_init has no effect" in mock_warning.call_args[0][0]


def test_no_warning_when_lazy_init_false_and_geo_ip_handler_configured() -> None:
    config = SecurityConfig(lazy_init=False)
    geo_ip = MagicMock()
    geo_ip.initialize = MagicMock()
    initializer = HandlerInitializer(
        config=config, redis_handler=None, geo_ip_handler=geo_ip
    )

    with patch.object(initializer.logger, "warning") as mock_warning:
        initializer.initialize_redis_handlers()

    mock_warning.assert_not_called()


def test_no_warning_when_lazy_init_inert_but_nothing_configured() -> None:
    config = SecurityConfig(lazy_init=True)
    initializer = HandlerInitializer(config=config, redis_handler=None)

    with patch.object(initializer.logger, "warning") as mock_warning:
        initializer.initialize_redis_handlers()

    mock_warning.assert_not_called()


def test_no_redis_eager_loads_cloud_when_lazy_init_false() -> None:
    config = SecurityConfig(
        lazy_init=False,
        enable_redis=False,
        block_cloud_providers={"AWS"},
    )
    geo_ip = MagicMock()
    geo_ip.initialize = MagicMock()
    geo_ip.initialize_redis = MagicMock()
    initializer = HandlerInitializer(
        config=config, redis_handler=None, geo_ip_handler=geo_ip
    )

    with _patch_handlers() as patches:
        initializer.initialize_redis_handlers()
        patches["cloud"].refresh.assert_called_once_with({"AWS"})
        patches["cloud"].initialize_redis.assert_not_called()

    geo_ip.initialize.assert_called_once()
    geo_ip.initialize_redis.assert_not_called()


def test_no_redis_eager_load_skips_cloud_when_no_providers() -> None:
    config = SecurityConfig(
        lazy_init=False,
        enable_redis=False,
        block_cloud_providers=set(),
    )
    geo_ip = MagicMock()
    geo_ip.initialize = MagicMock()
    initializer = HandlerInitializer(
        config=config, redis_handler=None, geo_ip_handler=geo_ip
    )

    with _patch_handlers() as patches:
        initializer.initialize_redis_handlers()
        patches["cloud"].refresh.assert_not_called()

    geo_ip.initialize.assert_called_once()


def test_no_redis_eager_load_skips_geo_when_no_geo_handler() -> None:
    config = SecurityConfig(
        lazy_init=False,
        enable_redis=False,
        block_cloud_providers={"AWS"},
    )
    initializer = HandlerInitializer(
        config=config, redis_handler=None, geo_ip_handler=None
    )

    with _patch_handlers() as patches:
        initializer.initialize_redis_handlers()
        patches["cloud"].refresh.assert_called_once_with({"AWS"})


def test_no_redis_lazy_init_true_does_not_eager_load_cloud() -> None:
    config = SecurityConfig(
        lazy_init=True,
        enable_redis=False,
        block_cloud_providers={"AWS"},
    )
    geo_ip = MagicMock()
    geo_ip.initialize = MagicMock()
    initializer = HandlerInitializer(
        config=config, redis_handler=None, geo_ip_handler=geo_ip
    )

    with _patch_handlers() as patches:
        with patch.object(initializer.logger, "warning") as mock_warning:
            initializer.initialize_redis_handlers()
            patches["cloud"].refresh.assert_not_called()
            geo_ip.initialize.assert_not_called()
            mock_warning.assert_called_once()
