import gc

from guard_core.models import SyncSecurityConfig
from guard_core.sync.core.initialization.handler_initializer import HandlerInitializer
from guard_core.sync.handlers.ipban_handler import ip_ban_manager
from guard_core.sync.handlers.redis_handler import RedisManager
from guard_core.sync.handlers.suspatterns_handler import (
    sus_patterns_handler,
    sus_patterns_manager_for,
)
from tests.test_sync.protocol_only_redis import REDIS_URL

_ROW = "[xyz]7"


def _run_a_redis_app_and_let_it_go() -> None:
    config = SyncSecurityConfig(
        enable_redis=True,
        redis_url=REDIS_URL,
        redis_prefix="wp492:gone:",
        enable_rate_limiting=False,
        enable_ip_banning=False,
    )
    handler = RedisManager(config)
    HandlerInitializer(config, redis_handler=handler).initialize_redis_handlers()
    handler.close()


def test_a_new_app_does_not_inherit_the_redis_handler_of_a_gone_app() -> None:
    _run_a_redis_app_and_let_it_go()
    gc.collect()
    second = SyncSecurityConfig(
        enable_redis=False, enable_rate_limiting=False, enable_ip_banning=False
    )
    HandlerInitializer(second).initialize_redis_handlers()
    try:
        assert sus_patterns_handler.redis_handler is None
        assert ip_ban_manager.redis_handler is None

        sus_patterns_manager_for(second).add_pattern(_ROW, custom=True)
    finally:
        sus_patterns_manager_for(second).remove_pattern(_ROW, custom=True)
