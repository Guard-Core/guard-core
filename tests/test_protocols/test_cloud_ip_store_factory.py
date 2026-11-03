def test_cloud_ip_store_factory_alias_exists() -> None:
    from guard_core.protocols.cloud_ip_store_protocol import CloudIpStoreFactory

    assert CloudIpStoreFactory is not None


def test_factory_accepts_redis_handler_returns_store() -> None:

    from guard_core.handlers.cloud_ip_stores import (
        InMemoryCloudIpStore,
        RedisCloudIpStore,
    )
    from guard_core.protocols.cloud_ip_store_protocol import CloudIpStoreFactory
    from guard_core.protocols.redis_protocol import RedisHandlerProtocol

    def make_redis_store(
        redis_handler: RedisHandlerProtocol | None,
    ) -> RedisCloudIpStore:
        assert redis_handler is not None
        return RedisCloudIpStore(redis_handler)

    def make_in_memory_store(
        redis_handler: RedisHandlerProtocol | None,
    ) -> InMemoryCloudIpStore:
        return InMemoryCloudIpStore()

    factory_one: CloudIpStoreFactory = make_redis_store
    factory_two: CloudIpStoreFactory = make_in_memory_store

    assert callable(factory_one)
    assert callable(factory_two)
