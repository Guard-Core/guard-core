import gc
import weakref
from collections.abc import Iterator
from contextlib import contextmanager
from unittest.mock import Mock

from guard_core.models import SyncSecurityConfig
from guard_core.sync._utils.app_scope import (
    app_scope_of,
    existing_app_scope_of,
    in_app_scope,
)
from guard_core.sync.handlers.cloud_handler import cloud_handler, cloud_handler_for
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


def test_a_config_with_an_app_scope_is_freed_by_refcount() -> None:
    with _no_gc():
        config = SyncSecurityConfig(enable_redis=False)
        app_scope_of(config)
        released = weakref.ref(config)

        del config

        assert released() is None


def test_the_scope_reads_its_config_while_the_app_holds_it() -> None:
    config = SyncSecurityConfig(enable_redis=False)

    scope = app_scope_of(config)

    assert scope.config is config
    assert existing_app_scope_of(config) is scope


def test_the_scope_of_a_dropped_config_reads_none_and_scopes_nothing() -> None:
    with _no_gc():
        config = SyncSecurityConfig(enable_redis=False)
        scope = app_scope_of(config)
        del config

        assert scope.config is None
        with in_app_scope(scope):
            assert scope.redis_handler is None


def test_the_next_app_binds_the_module_cloud_handler_once_the_first_is_dropped() -> (
    None
):
    with _no_gc():
        first = _redis_config("wp466-first")
        app_scope_of(first)
        assert cloud_handler_for(first, bind=True) is cloud_handler
        del first
        second = _redis_config("wp466-second")

        assert cloud_handler_for(second, bind=True) is cloud_handler


def test_two_live_apps_on_different_prefixes_still_get_separate_managers() -> None:
    first = _redis_config("wp466-live-first")
    second = _redis_config("wp466-live-second")
    app_scope_of(first)

    assert cloud_handler_for(first, bind=True) is cloud_handler
    assert cloud_handler_for(second, bind=True) is not cloud_handler


def test_the_scope_handlers_are_released_with_the_config() -> None:
    with _no_gc():
        config = SyncSecurityConfig(enable_redis=False)
        scope = app_scope_of(config)
        redis_handler, agent_handler = Mock(), Mock()
        scope.redis_handler = redis_handler
        scope.agent_handler = agent_handler
        released = (weakref.ref(redis_handler), weakref.ref(agent_handler))
        del redis_handler, agent_handler, scope, config

        assert [ref() for ref in released] == [None, None]
