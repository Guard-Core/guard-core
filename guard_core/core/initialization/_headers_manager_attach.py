from guard_core.handlers.redis_handler import is_connected_redis_manager
from guard_core.handlers.security_headers_handler import security_headers_manager
from guard_core.models import SecurityConfig
from guard_core.protocols.redis_protocol import RedisHandlerProtocol


async def attach_security_headers_manager_to_redis(
    redis_handler: RedisHandlerProtocol | None, config: SecurityConfig
) -> None:
    # Only a connected, real handler: the manager reads and writes through it, and
    # an unconnected one would only retry its own connection on every operation.
    if security_headers_manager.redis_handler is None and is_connected_redis_manager(
        redis_handler
    ):
        await security_headers_manager.initialize_redis(redis_handler, config)
