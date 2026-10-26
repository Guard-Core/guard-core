from guard_core.models import SyncSecurityConfig
from guard_core.sync.handlers.redis_handler import is_connected_redis_manager
from guard_core.sync.handlers.security_headers_handler import security_headers_manager
from guard_core.sync.protocols.redis_protocol import SyncRedisHandlerProtocol


def attach_security_headers_manager_to_redis(
    redis_handler: SyncRedisHandlerProtocol | None, config: SyncSecurityConfig
) -> None:
    # Only a connected, real handler: the manager reads and writes through it, and
    # an unconnected one would only retry its own connection on every operation.
    if (
        redis_handler is not None
        and security_headers_manager.redis_handler is None
        and is_connected_redis_manager(redis_handler)
    ):
        security_headers_manager.initialize_redis(redis_handler, config)
