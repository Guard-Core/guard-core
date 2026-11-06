import gc
import logging
import warnings
import weakref
from collections.abc import Iterator
from contextlib import contextmanager
from types import SimpleNamespace
from typing import Any

import pytest

from guard_core.core.initialization._ban_threshold_report import (
    log_unreachable_ban_thresholds_after_rule_change,
)
from guard_core.core.initialization.handler_initializer import HandlerInitializer
from guard_core.decorators.route_config import RouteConfig
from guard_core.handlers._background_stop import stop_before_redis_closes
from guard_core.handlers.redis_handler import RedisManager
from guard_core.models import SecurityConfig
from tests.protocol_only_redis import REDIS_URL


@contextmanager
def _no_gc() -> Iterator[None]:
    gc.collect()
    gc.disable()
    try:
        yield
    finally:
        gc.enable()


def _config(**overrides: object) -> SecurityConfig:
    values: dict[str, Any] = {
        "enable_redis": False,
        "rate_limit": 1,
        "rate_limit_window": 60,
        "auto_ban_threshold": 100_000,
        "fail_on_misconfiguration": False,
    }
    values.update(overrides)
    return SecurityConfig(**values)


def _initializer_with_routes(
    config: SecurityConfig, bypassed_checks: set[str]
) -> HandlerInitializer:
    route = RouteConfig()
    route.bypassed_checks = bypassed_checks
    decorator: Any = SimpleNamespace(_route_configs={"route": route})
    initializer = HandlerInitializer(config, guard_decorator=decorator)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        initializer._report_unreachable_ban_thresholds()
    return initializer


def _warnings_after_rule_change(
    config: SecurityConfig, caplog: pytest.LogCaptureFixture
) -> list[str]:
    with caplog.at_level(logging.WARNING, logger="wp467-side"):
        log_unreachable_ban_thresholds_after_rule_change(
            config, logging.getLogger("wp467-side")
        )
    return [r.getMessage() for r in caplog.records if r.name == "wp467-side"]


async def test_a_background_stop_of_a_gone_app_does_not_keep_its_config_alive() -> None:
    with _no_gc():
        config = SecurityConfig(
            enable_redis=True, redis_url=REDIS_URL, redis_prefix="wp467b-bg:"
        )
        initializer = HandlerInitializer(config)
        held_by_a_module = RedisManager(config)
        stop_before_redis_closes(held_by_a_module, initializer._stop_lazy_init)
        released = weakref.ref(config)

        del config, initializer

        assert released() is None
        assert list(held_by_a_module._background_user_set()) == []


async def test_a_background_stop_of_a_live_owner_still_runs_on_close() -> None:
    calls: list[str] = []

    class Owner:
        async def stop(self) -> None:
            calls.append("stopped")

    owner = Owner()
    manager = RedisManager(SecurityConfig(enable_redis=False))
    stop_before_redis_closes(manager, owner.stop)
    stop_before_redis_closes(manager, owner.stop)

    await manager.close()

    assert calls == ["stopped"]


async def test_the_remembered_context_of_a_gone_app_is_freed_by_refcount() -> None:
    with _no_gc():
        config = _config()
        _initializer_with_routes(config, set())
        released = weakref.ref(config)

        del config

        assert released() is None


async def test_a_rule_change_is_checked_against_the_routes_of_its_own_app(
    caplog: pytest.LogCaptureFixture,
) -> None:
    first = _config()
    second = _config()
    keep_first = _initializer_with_routes(first, set())
    keep_second = _initializer_with_routes(second, {"rate_limit"})

    assert len(_warnings_after_rule_change(first, caplog)) == 1
    caplog.clear()
    assert _warnings_after_rule_change(second, caplog) == []
    assert keep_first is not keep_second
