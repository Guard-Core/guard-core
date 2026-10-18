from typing import Any

from guard_core.models import SecurityConfig
from guard_core.sync.handlers.redis_handler import RedisManager
from guard_core.sync.handlers.security_headers_handler import security_headers_manager


def attach_security_headers_manager_to_redis(
    redis_handler: Any, config: SecurityConfig
) -> None:
    # Only the real connection handler: the manager reads and writes through it.
    if security_headers_manager.redis_handler is None and isinstance(
        redis_handler, RedisManager
    ):
        security_headers_manager.initialize_redis(redis_handler, config)
