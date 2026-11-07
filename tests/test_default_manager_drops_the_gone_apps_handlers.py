import gc

from guard_core.core.initialization.handler_initializer import HandlerInitializer
from guard_core.handlers.ipban_handler import ip_ban_manager
from guard_core.handlers.redis_handler import RedisManager
from guard_core.handlers.suspatterns_handler import (
    sus_patterns_handler,
    sus_patterns_manager_for,
)
from guard_core.models import SecurityConfig
from tests.protocol_only_redis import REDIS_URL

_ROW = "[xyz]7"


async def _run_a_redis_app_and_let_it_go() -> None:
    config = SecurityConfig(
        enable_redis=True,
        redis_url=REDIS_URL,
        redis_prefix="wp492:gone:",
        enable_rate_limiting=False,
        enable_ip_banning=False,
    )
    handler = RedisManager(config)
    await HandlerInitializer(config, redis_handler=handler).initialize_redis_handlers()
    await handler.close()


async def test_a_new_app_does_not_inherit_the_redis_handler_of_a_gone_app() -> None:
    await _run_a_redis_app_and_let_it_go()
    gc.collect()
    second = SecurityConfig(
        enable_redis=False, enable_rate_limiting=False, enable_ip_banning=False
    )
    await HandlerInitializer(second).initialize_redis_handlers()
    try:
        assert sus_patterns_handler.redis_handler is None
        assert ip_ban_manager.redis_handler is None

        await sus_patterns_manager_for(second).add_pattern(_ROW, custom=True)
    finally:
        await sus_patterns_manager_for(second).remove_pattern(_ROW, custom=True)
