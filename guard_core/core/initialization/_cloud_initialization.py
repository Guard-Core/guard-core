import asyncio
from typing import TYPE_CHECKING, Any, TypeGuard

from guard_core._security_config_cloud_store_validators import (
    _CLOUD_IP_STORE_MEMBERS,
)
from guard_core._utils.capability import has_callables
from guard_core.protocols.cloud_ip_store_protocol import CloudIpStoreProtocol

if TYPE_CHECKING:
    from guard_core.models import SecurityConfig
    from guard_core.protocols.cloud_ip_store_protocol import CloudIpStoreFactory


def _is_cloud_ip_store_factory(store: object) -> TypeGuard["CloudIpStoreFactory"]:
    return isinstance(store, type) or (
        callable(store) and not has_callables(store, _CLOUD_IP_STORE_MEMBERS)
    )


def _is_cloud_ip_store(store: object) -> TypeGuard[CloudIpStoreProtocol]:
    return store is not None and not _is_cloud_ip_store_factory(store)


class CloudInitializationMixin:
    config: "SecurityConfig"
    redis_handler: Any = None
    geo_ip_handler: Any = None
    guard_decorator: Any = None
    _lazy_init_task: "asyncio.Task[None] | None" = None

    async def _run_lazy_init(self) -> None: ...

    def _cloud_providers_to_load(self) -> frozenset[str]:
        providers = set(self.config.block_cloud_providers or ())
        route_configs = getattr(self.guard_decorator, "_route_configs", {})
        for route_config in route_configs.values():
            providers.update(route_config.block_cloud_providers)
        return frozenset(providers)

    def _resolve_cloud_ip_store(self) -> CloudIpStoreProtocol:
        store = self.config.cloud_ip_store
        if _is_cloud_ip_store_factory(store):
            return store(self.redis_handler)
        if _is_cloud_ip_store(store):
            return store
        raise TypeError("cloud_ip_store is neither a store nor a store factory")

    async def _load_cloud_and_geo_without_redis(self) -> None:
        from guard_core.handlers.cloud_handler import cloud_handler_for

        if self.config.cloud_ip_store is not None:
            cloud_handler_for(self.config).set_store(self._resolve_cloud_ip_store())
        if providers := self._cloud_providers_to_load():
            await cloud_handler_for(self.config).refresh(providers)
        if self.geo_ip_handler is not None:
            await self.geo_ip_handler.initialize()

    async def _initialize_cloud_and_geo_redis(self) -> None:
        from guard_core.handlers.cloud_handler import cloud_handler_for

        if self.config.lazy_init:
            self._lazy_init_task = asyncio.create_task(self._run_lazy_init())
            return
        if providers := self._cloud_providers_to_load():
            await cloud_handler_for(self.config).initialize_redis(
                self.redis_handler,
                providers,
                ttl=self.config.cloud_ip_refresh_interval,
            )
        if self.geo_ip_handler is not None:
            await self.geo_ip_handler.initialize_redis(self.redis_handler)
