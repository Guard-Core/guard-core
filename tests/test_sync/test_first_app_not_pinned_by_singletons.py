import gc
import weakref
from collections.abc import Iterator
from contextlib import contextmanager

from guard_core.models import SyncSecurityConfig
from guard_core.sync.core.initialization.handler_initializer import HandlerInitializer
from guard_core.sync.handlers.cloud_handler import cloud_handler, cloud_handler_for
from guard_core.sync.handlers.dynamic_rule_handler import (
    DynamicRuleManager,
    dynamic_rule_manager_of_the_app,
)
from guard_core.sync.handlers.ipban_handler import ip_ban_manager, ip_ban_manager_for
from guard_core.sync.handlers.redis_handler import RedisManager
from guard_core.sync.handlers.security_headers_handler import security_headers_manager
from guard_core.sync.handlers.suspatterns_handler import (
    sus_patterns_handler,
    sus_patterns_manager_for,
)
from tests.test_sync.protocol_only_redis import REDIS_URL


@contextmanager
def _no_gc() -> Iterator[None]:
    gc.collect()
    gc.disable()
    try:
        yield
    finally:
        gc.enable()


def _redis_config(prefix: str) -> SyncSecurityConfig:
    return SyncSecurityConfig(
        enable_redis=True, redis_url=REDIS_URL, redis_prefix=prefix
    )


def _start_app(prefix: str) -> SyncSecurityConfig:
    config = _redis_config(prefix)
    HandlerInitializer(config).initialize_redis_handlers()
    dynamic_rule_manager_of_the_app(config)
    return config


def test_the_first_app_is_freed_by_refcount_once_it_is_gone() -> None:
    with _no_gc():
        first = _start_app("wp467-first:")
        released = weakref.ref(first)

        del first

        assert released() is None


def test_the_first_app_with_a_redis_handler_is_freed_by_refcount() -> None:
    with _no_gc():
        first = _redis_config("wp467-redis:")
        handler = RedisManager(first)
        HandlerInitializer(first, redis_handler=handler).initialize_redis_handlers()
        ip_ban_manager.redis_handler = handler
        sus_patterns_handler.redis_handler = handler
        security_headers_manager.redis_handler = handler
        released = weakref.ref(first)

        del first
        gc.collect()  # the initializer and its behavior tracker are one cycle

        assert released() is None
        assert "config" not in vars(handler)
        ip_ban_manager.redis_handler = None
        sus_patterns_handler.redis_handler = None
        security_headers_manager.redis_handler = None


def test_a_redis_manager_built_by_hand_keeps_its_config() -> None:
    with _no_gc():
        manager = RedisManager(_redis_config("wp467-hand:"))

        assert manager.config is not None
        assert manager.config.redis_prefix == "wp467-hand:"


def test_the_next_app_on_another_prefix_is_served_by_the_module_singletons() -> None:
    with _no_gc():
        first = _start_app("wp467-gone:")
        del first
        second = _start_app("wp467-next:")

        assert cloud_handler_for(second) is cloud_handler
        assert ip_ban_manager_for(second) is ip_ban_manager
        assert sus_patterns_manager_for(second) is sus_patterns_handler
        assert DynamicRuleManager(second) is DynamicRuleManager._instance
        assert DynamicRuleManager(second).config is second
        assert ip_ban_manager.config is second


def test_a_single_live_app_is_served_by_the_module_singletons() -> None:
    first = _start_app("wp467-single:")

    assert cloud_handler_for(first) is cloud_handler
    assert ip_ban_manager_for(first) is ip_ban_manager
    assert sus_patterns_manager_for(first) is sus_patterns_handler
    assert ip_ban_manager.config is first


def test_two_live_apps_on_different_prefixes_keep_separate_managers() -> None:
    first = _start_app("wp467-live-first:")
    second = _start_app("wp467-live-second:")

    assert cloud_handler_for(first) is cloud_handler
    assert cloud_handler_for(second) is not cloud_handler
    assert ip_ban_manager_for(second) is not ip_ban_manager
    assert sus_patterns_manager_for(second) is not sus_patterns_handler


def test_a_config_assigned_inline_to_the_ban_manager_stays() -> None:
    with _no_gc():
        ip_ban_manager.config = SyncSecurityConfig(enable_redis=False)

        assert ip_ban_manager.config is not None
