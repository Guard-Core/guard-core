from collections.abc import Callable
from typing import Protocol, runtime_checkable

from guard_core.sync.protocols.redis_protocol import SyncRedisHandlerProtocol


@runtime_checkable
class SyncCloudIpStoreProtocol(Protocol):
    """Cache of cloud-provider IP ranges consulted by the cloud-IP check.

    WHAT: per-provider sets of CIDR strings (e.g. ``"AWS"`` -> ranges) that
    back ``block_cloud_providers`` matching.
    WHEN: ``get`` is hit on the request hot path for every configured provider;
    ``set`` is populated by the periodic range refresh, ``clear`` on reset.
    HOW: back it with the shared store so all workers share one cache. ``get``
    returns ``None`` on a miss (distinct from an empty set, which means "known,
    no ranges") so the caller can decide whether to trigger a refresh.
    """

    def get(self, provider: str) -> set[str] | None:
        """Return cached ranges for ``provider``, or ``None`` if not cached."""
        ...

    def set(self, provider: str, ranges: set[str], ttl: int | None = None) -> None:
        """Cache ``ranges`` for ``provider``, expiring after ``ttl`` seconds."""
        ...

    def clear(self) -> None:
        """Drop all cached provider ranges."""
        ...


SyncCloudIpStoreFactory = Callable[[SyncRedisHandlerProtocol], SyncCloudIpStoreProtocol]
