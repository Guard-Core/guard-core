---

title: Cloud IP Store
description: API reference for CloudIpStoreProtocol, InMemoryCloudIpStore, and RedisCloudIpStore
keywords: cloud ip store, redis, in-memory, cloud manager, guard-core
---

Cloud IP Store
==============

`CloudIpStoreProtocol` defines the pluggable backend for cached cloud-provider IP ranges. Guard-core ships two concrete implementations, `InMemoryCloudIpStore` and `RedisCloudIpStore`, and the active store can be swapped via `SecurityConfig.cloud_ip_store`.

___

CloudIpStoreProtocol
--------------------

**Location**: `guard_core/protocols/cloud_ip_store_protocol.py`

```python
from typing import Protocol, runtime_checkable


@runtime_checkable
class CloudIpStoreProtocol(Protocol):
    async def get(self, provider: str) -> set[str] | None: ...
    async def set(
        self, provider: str, ranges: set[str], ttl: int | None = None
    ) -> None: ...
    async def clear(self) -> None: ...
```

| Method                          | Description                                                                          |
|---------------------------------|--------------------------------------------------------------------------------------|
| `get(provider)`                 | Return the cached CIDR set for the provider, or `None` if absent.                    |
| `set(provider, ranges, ttl=)`   | Cache the CIDR set for the provider. `ttl` is honored by stores that support it.     |
| `clear()`                       | Drop all cached entries.                                                             |

A sync mirror lives at `guard_core/sync/protocols/cloud_ip_store_protocol.py` as `SyncCloudIpStoreProtocol`.

___

InMemoryCloudIpStore
--------------------

**Location**: `guard_core/handlers/cloud_ip_stores.py`

```python
class InMemoryCloudIpStore:
    def __init__(self) -> None: ...
    async def get(self, provider: str) -> set[str] | None: ...
    async def set(
        self, provider: str, ranges: set[str], ttl: int | None = None
    ) -> None: ...
    async def clear(self) -> None: ...
```

Process-local dictionary backed store. The `ttl` argument is accepted for protocol compatibility but is not enforced. This is the default store when no Redis is configured.

___

RedisCloudIpStore
-----------------

**Location**: `guard_core/handlers/cloud_ip_stores.py`

```python
class RedisCloudIpStore:
    def __init__(
        self,
        redis_handler: RedisHandlerProtocol,
        key_prefix: str = "cloud_ip_v2",
    ) -> None: ...
    async def get(self, provider: str) -> set[str] | None: ...
    async def set(
        self, provider: str, ranges: set[str], ttl: int | None = None
    ) -> None: ...
    async def clear(self) -> None: ...
```

Redis-backed store. Each provider's CIDR set is JSON-encoded as a sorted list and written under `<redis_prefix><key_prefix>:<provider>` (the `RedisManager.set_key` path already prepends `config.redis_prefix`, so `key_prefix` should not duplicate it). `set()` honors the optional `ttl`. `clear()` removes every key under the resolved prefix.

___

Backends
--------

### Default (auto-constructed)

When `enable_redis=True` and `block_cloud_providers` is set, guard-core automatically wires a `RedisCloudIpStore` during `HandlerInitializer.initialize_redis_handlers()` so cloud-IP ranges persist across worker restarts and stay shared across replicas. No `cloud_ip_store=` setting is required.

```python
from guard_core.models import SecurityConfig

config = SecurityConfig(
    enable_redis=True,
    redis_url="redis://localhost:6379",
    redis_prefix="myapp:guard:",
    block_cloud_providers={"AWS", "GCP", "Azure"},
)
```

Cloud-IP ranges land at Redis keys like `myapp:guard:cloud_ip_v2:AWS`. `RedisManager.set_key` already prepends `redis_prefix`, so the `key_prefix` default does not duplicate it.

When `enable_redis=False` (or no Redis URL is reachable), the same path falls back to `InMemoryCloudIpStore`, fine for single-process deployments, lost on restart.

### Custom prefix or implementation via callable

`cloud_ip_store` accepts a `CloudIpStoreFactory` callable: `Callable[[RedisHandlerProtocol | None], CloudIpStoreProtocol]`. The handler initializer invokes it with the live Redis handler once Redis is up, and with `None` when Redis is off, so user code never has to construct a throwaway `RedisManager` purely to feed the store.

```python
from guard_core.handlers.cloud_ip_stores import RedisCloudIpStore
from guard_core.models import SecurityConfig

config = SecurityConfig(
    enable_redis=True,
    redis_url="redis://localhost:6379",
    cloud_ip_store=lambda redis: RedisCloudIpStore(redis, key_prefix="cloud_ip_v2"),
)
```

### Custom non-Redis implementation via instance

If the store does not need a Redis handle (in-memory, DynamoDB, SQL, etc.), pass an instance directly:

```python
from guard_core.models import SecurityConfig

config = SecurityConfig(
    cloud_ip_store=MyDynamoDBCloudIpStore(table_name="cloud_ips"),
)
```

The instance is wired straight into `cloud_handler.set_store(...)` after Redis bootstrap. Combined with `lazy_init=True` (the default), the first cloud-IP fetch happens in a background task, application startup does not block on it.

___

Redis namespace migration
-------------------------

The v2.0.0 release moved the cloud-IP cache from the legacy `cloud_ranges` namespace (comma-separated CSV values per provider) to a JSON-encoded-sorted-list namespace, prefixed by `redis_prefix`; that namespace was itself later renamed to `cloud_ip_v2` when region-carve-out support (`"GCP:!us-central1"`-style selectors) was added, and the legacy read path's namespace was renamed to `cloud_ranges_v2` to match.

- **Default writers**: `RedisCloudIpStore` writes to `<redis_prefix>cloud_ip_v2:<provider>`.
- **Legacy reader (dead code)**: the legacy CSV path under `cloud_ranges_v2` is gated behind `CloudManager._store is None`. Because `CloudManager.__new__` always seeds `_store` with an `InMemoryCloudIpStore()` and nothing resets it to `None`, that branch is unreachable at runtime; the default and the Redis store both use the `cloud_ip_v2` namespace.

Any ops tooling, dashboards, or sidecars reading those Redis keys directly must switch to the new namespace. On upgrade from a previous release, the cache invalidates once and repopulates within `cloud_ip_refresh_interval`.

___

See also
--------

- [SecurityConfig - IP Lifecycle Controls](../configuration/security-config.md#ip-lifecycle-controls)
- [Internals - Cloud Providers](../internals/cloud-providers.md)
