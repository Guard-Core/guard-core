import threading
from typing import TYPE_CHECKING, TypeGuard

from guard_core._security_config_cloud_store_validators import (
    _CLOUD_IP_STORE_MEMBERS,
)
from guard_core.sync._utils.capability import has_callables
from guard_core.sync.protocols.cloud_ip_store_protocol import SyncCloudIpStoreProtocol

if TYPE_CHECKING:
    from guard_core.models import SyncSecurityConfig
    from guard_core.sync.decorators.base import BaseSecurityDecorator
    from guard_core.sync.protocols.cloud_ip_store_protocol import (
        SyncCloudIpStoreFactory,
    )
    from guard_core.sync.protocols.geo_ip_protocol import SyncGeoIPHandler
    from guard_core.sync.protocols.redis_protocol import SyncRedisHandlerProtocol


def _is_cloud_ip_store_factory(store: object) -> TypeGuard["SyncCloudIpStoreFactory"]:
    return isinstance(store, type) or (
        callable(store) and not has_callables(store, _CLOUD_IP_STORE_MEMBERS)
    )


def _is_cloud_ip_store(store: object) -> TypeGuard[SyncCloudIpStoreProtocol]:
    return store is not None and not _is_cloud_ip_store_factory(store)


class CloudInitializationMixin:
    config: "SyncSecurityConfig"
    redis_handler: "SyncRedisHandlerProtocol | None" = None
    geo_ip_handler: "SyncGeoIPHandler | None" = None
    guard_decorator: "BaseSecurityDecorator | None" = None
    _lazy_init_task: "threading.Thread | None" = None

    def _run_lazy_init(self) -> None: ...

    def _cloud_providers_to_load(self) -> frozenset[str]:
        providers = set(self.config.block_cloud_providers or ())
        route_configs = getattr(self.guard_decorator, "_route_configs", {})
        for route_config in route_configs.values():
            providers.update(route_config.block_cloud_providers)
        return frozenset(providers)

    def _resolve_cloud_ip_store(self) -> SyncCloudIpStoreProtocol:
        store = self.config.cloud_ip_store
        if _is_cloud_ip_store_factory(store):
            return store(self.redis_handler)
        if _is_cloud_ip_store(store):
            return store
        raise TypeError("cloud_ip_store is neither a store nor a store factory")

    def _load_cloud_and_geo_without_redis(self) -> None:
        from guard_core.sync.handlers.cloud_handler import cloud_handler_for

        if self.config.cloud_ip_store is not None:
            cloud_handler_for(self.config).set_store(self._resolve_cloud_ip_store())
        if providers := self._cloud_providers_to_load():
            cloud_handler_for(self.config).refresh(providers)
        if self.geo_ip_handler is not None:
            self.geo_ip_handler.initialize()

    def _initialize_cloud_and_geo_redis(
        self, redis_handler: "SyncRedisHandlerProtocol"
    ) -> None:
        from guard_core.sync.handlers.cloud_handler import cloud_handler_for

        if self.config.lazy_init:
            self._lazy_init_task = threading.Thread(
                target=self._run_lazy_init, daemon=True
            )
            self._lazy_init_task.start()
            return
        if providers := self._cloud_providers_to_load():
            cloud_handler_for(self.config).initialize_redis(
                redis_handler,
                providers,
                ttl=self.config.cloud_ip_refresh_interval,
            )
        if self.geo_ip_handler is not None:
            self.geo_ip_handler.initialize_redis(redis_handler)
