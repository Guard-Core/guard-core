import os
import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager

from typing_extensions import get_protocol_members

from guard_core.models import SecurityConfig
from guard_core.sync.handlers.redis_handler import RedisManager
from guard_core.sync.protocols.redis_protocol import SyncRedisHandlerProtocol

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379")
MEMBERS = get_protocol_members(SyncRedisHandlerProtocol)


class ProtocolOnlyHandler:
    """Exposes exactly the members SyncRedisHandlerProtocol declares and records which
    of them the engine used, so a call to anything else is an AttributeError."""

    def __init__(self, inner: RedisManager) -> None:
        self.config = inner.config
        self.used: set[str] = set()
        for name in MEMBERS - {"config"}:
            setattr(self, name, self._recording(name, getattr(inner, name)))

    def _recording(
        self, name: str, method: Callable[..., object]
    ) -> Callable[..., object]:
        def call(*args: object, **kwargs: object) -> object:
            self.used.add(name)
            return method(*args, **kwargs)

        return call


@contextmanager
def protocol_only_handler(
    prefix: str = "wp69", **config: object
) -> Iterator[ProtocolOnlyHandler]:
    manager = RedisManager(
        SecurityConfig.model_validate(
            {
                "enable_redis": True,
                "redis_url": REDIS_URL,
                "redis_prefix": f"{prefix}:{uuid.uuid4().hex}:",
                "enable_rate_limiting": True,
                "enable_ip_banning": True,
                "enable_penetration_detection": True,
                "whitelist": ["127.0.0.1"],
                **config,
            }
        )
    )
    manager.initialize()
    try:
        yield ProtocolOnlyHandler(manager)
    finally:
        manager.delete_pattern("*")
        manager.close()
