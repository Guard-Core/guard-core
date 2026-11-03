def test_cloud_ip_store_factory_alias_exists() -> None:
    from guard_core.sync.protocols.cloud_ip_store_protocol import (
        SyncCloudIpStoreFactory,
    )

    assert SyncCloudIpStoreFactory is not None


def test_factory_accepts_redis_handler_returns_store() -> None:

    from guard_core.sync.handlers.cloud_ip_stores import (
        InMemoryCloudIpStore,
        RedisCloudIpStore,
    )
    from guard_core.sync.protocols.cloud_ip_store_protocol import (
        SyncCloudIpStoreFactory,
    )
    from guard_core.sync.protocols.redis_protocol import SyncRedisHandlerProtocol

    def make_redis_store(
        redis_handler: SyncRedisHandlerProtocol | None,
    ) -> RedisCloudIpStore:
        assert redis_handler is not None
        return RedisCloudIpStore(redis_handler)

    def make_in_memory_store(
        redis_handler: SyncRedisHandlerProtocol | None,
    ) -> InMemoryCloudIpStore:
        return InMemoryCloudIpStore()

    factory_one: SyncCloudIpStoreFactory = make_redis_store
    factory_two: SyncCloudIpStoreFactory = make_in_memory_store

    assert callable(factory_one)
    assert callable(factory_two)
