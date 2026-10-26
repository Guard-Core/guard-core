from guard_core.models import SyncSecurityConfig
from guard_core.sync.core.initialization._cloud_initialization import (
    CloudInitializationMixin,
)
from guard_core.sync.protocols.redis_protocol import SyncRedisHandlerProtocol


class _Store:
    def get(self, provider: str) -> set[str] | None:
        return None

    def set(self, provider: str, ranges: set[str], ttl: int | None = None) -> None:
        return None

    def clear(self) -> None:
        return None


class _Initializer(CloudInitializationMixin):
    def __init__(self, config: SyncSecurityConfig) -> None:
        self.config = config


def test_the_factory_receives_none_when_redis_is_off() -> None:
    received: list[SyncRedisHandlerProtocol | None] = []

    def factory(redis_handler: SyncRedisHandlerProtocol | None) -> _Store:
        received.append(redis_handler)
        return _Store()

    config = SyncSecurityConfig(enable_redis=False, cloud_ip_store=factory)
    _Initializer(config)._load_cloud_and_geo_without_redis()
    assert received == [None]
