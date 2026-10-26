from guard_core.core.initialization._cloud_initialization import (
    CloudInitializationMixin,
)
from guard_core.models import SecurityConfig
from guard_core.protocols.redis_protocol import RedisHandlerProtocol


class _Store:
    async def get(self, provider: str) -> set[str] | None:
        return None

    async def set(
        self, provider: str, ranges: set[str], ttl: int | None = None
    ) -> None:
        return None

    async def clear(self) -> None:
        return None


class _Initializer(CloudInitializationMixin):
    def __init__(self, config: SecurityConfig) -> None:
        self.config = config


async def test_the_factory_receives_none_when_redis_is_off() -> None:
    received: list[RedisHandlerProtocol | None] = []

    def factory(redis_handler: RedisHandlerProtocol | None) -> _Store:
        received.append(redis_handler)
        return _Store()

    config = SecurityConfig(enable_redis=False, cloud_ip_store=factory)
    await _Initializer(config)._load_cloud_and_geo_without_redis()
    assert received == [None]
