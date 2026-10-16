import logging
from typing import Any

from cachetools import TTLCache

from guard_core.handlers._ipban_bans import _LOOPBACK_NETWORKS, IpBanOperationsMixin
from guard_core.handlers._ipban_cache import _Network, _ObservableTTLCache
from guard_core.handlers._ipban_migration import (
    _BANNED_IPS_NAMESPACE,
    IpBanMigrationMixin,
    _close_if_unusable,
)
from guard_core.handlers._ipban_queries import IpBanQueryMixin
from guard_core.utils import _canonicalize_ip

__all__ = [
    "IPBanManager",
    "_BANNED_IPS_NAMESPACE",
    "_LOOPBACK_NETWORKS",
    "_Network",
    "_ObservableTTLCache",
    "_canonicalize_ip",
    "_close_if_unusable",
    "ip_ban_manager",
    "reset_global_state",
]


class IPBanManager(IpBanMigrationMixin, IpBanOperationsMixin, IpBanQueryMixin):
    LOCAL_CACHE_TTL_CAP_SECONDS = 3600
    _EVICTION_LOG_EVERY = 100

    _instance: "IPBanManager | None" = None
    banned_ips: TTLCache
    banned_networks: list[tuple[_Network, float]]
    evictions_count: int
    logger: logging.Logger
    config: Any = None
    redis_handler: Any = None
    agent_handler: Any = None

    def __new__(cls: type["IPBanManager"]) -> "IPBanManager":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance.evictions_count = 0
            cls._instance.logger = logging.getLogger("guard_core.handlers.ipban")
            cls._instance.banned_ips = _ObservableTTLCache(
                maxsize=10000,
                ttl=cls.LOCAL_CACHE_TTL_CAP_SECONDS,
                on_evict=cls._instance._on_eviction,
            )
            cls._instance.banned_networks = []
            cls._instance.rule_exempt_networks = ()
            cls._instance.redis_handler = None
            cls._instance.agent_handler = None
        return cls._instance

    def _on_eviction(self) -> None:
        self.evictions_count += 1
        if self.evictions_count % self._EVICTION_LOG_EVERY == 0:
            self.logger.warning(
                "IP ban cache full; %d entries evicted (silent overflow)",
                self.evictions_count,
            )


ip_ban_manager = IPBanManager()


async def reset_global_state() -> None:
    global ip_ban_manager
    manager = IPBanManager()
    manager.banned_ips.clear()
    manager.banned_networks = []
    manager.rule_exempt_networks = ()
    manager.evictions_count = 0
    manager.redis_handler = None
    manager.agent_handler = None
    ip_ban_manager = manager
