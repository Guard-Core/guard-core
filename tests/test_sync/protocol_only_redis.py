import os
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from typing_extensions import get_protocol_members

from guard_core.models import SyncSecurityConfig
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

    def _recording(self, name: str, method: Any) -> Any:
        def call(*args: Any, **kwargs: Any) -> Any:
            self.used.add(name)
            return method(*args, **kwargs)

        return call


@contextmanager
def protocol_only_handler(
    prefix: str = "wp69", **config: Any
) -> Iterator[ProtocolOnlyHandler]:
    manager = RedisManager(
        SyncSecurityConfig(
            enable_redis=True,
            redis_url=REDIS_URL,
            redis_prefix=f"{prefix}:{uuid.uuid4().hex}:",
            enable_rate_limiting=True,
            enable_ip_banning=True,
            enable_penetration_detection=True,
            whitelist=["127.0.0.1"],
            **config,
        )
    )
    manager.initialize()
    try:
        yield ProtocolOnlyHandler(manager)
    finally:
        manager.delete_pattern("*")
        manager.close()
