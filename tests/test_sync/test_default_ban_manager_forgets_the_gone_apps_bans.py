import gc
from collections.abc import Iterator

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync._utils.app_managers import release_app
from guard_core.sync.core.initialization.handler_initializer import HandlerInitializer
from guard_core.sync.handlers import ipban_handler as ipban_module
from guard_core.sync.handlers.ipban_handler import ip_ban_manager_for
from tests.test_sync.protocol_only_redis import REDIS_URL

_IP = "203.0.113.70"


@pytest.fixture(autouse=True)
def _ban_default_unserved() -> Iterator[None]:
    ipban_module._APP_BAN_MANAGERS.forget_default()
    ipban_module.ip_ban_manager.banned_ips.clear()
    yield
    ipban_module._APP_BAN_MANAGERS.forget_default()
    ipban_module.ip_ban_manager.banned_ips.clear()


def _memory_app() -> SyncSecurityConfig:
    return SyncSecurityConfig(enable_redis=False)


def _shared_prefix_app() -> SyncSecurityConfig:
    return SyncSecurityConfig(
        enable_redis=True, redis_url=REDIS_URL, redis_prefix="wp616:ban-shared:"
    )


def _ban_through_a_first_app_and_end_it(ended_by: str) -> None:
    first = _memory_app()
    HandlerInitializer(first)
    assert ip_ban_manager_for(first).ban_ip(_IP, 600)
    app: dict[str, object] = {"config": first}
    app["self"] = app
    if ended_by == "release":
        release_app(first)


@pytest.mark.parametrize("ended_by", ["release", "collected"])
def test_the_next_app_does_not_inherit_the_in_memory_bans_of_the_gone_app(
    ended_by: str,
) -> None:
    _ban_through_a_first_app_and_end_it(ended_by)
    if ended_by == "collected":
        gc.collect()
    second = _memory_app()
    HandlerInitializer(second)
    manager = ip_ban_manager_for(second)
    assert manager is ipban_module.ip_ban_manager
    assert not manager.is_ip_banned(_IP, config=second)


def test_a_sharing_app_keeps_the_bans_after_the_other_is_released() -> None:
    first, second = _shared_prefix_app(), _shared_prefix_app()
    HandlerInitializer(first)
    HandlerInitializer(second)
    assert ip_ban_manager_for(first).ban_ip(_IP, 600, config=first)
    release_app(first)
    manager = ip_ban_manager_for(second)
    assert manager is ipban_module.ip_ban_manager
    assert manager.is_ip_banned(_IP, config=second)
