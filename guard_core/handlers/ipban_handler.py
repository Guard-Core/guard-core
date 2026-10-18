import logging
from collections.abc import MutableMapping
from typing import Any

from guard_core.handlers._ipban_bans import _LOOPBACK_NETWORKS, IpBanOperationsMixin
from guard_core.handlers._ipban_cache import (
    DEFAULT_MAX_LOCAL_BANS,
    _BanStore,
    _Network,
    _ObservableTTLCache,
)
from guard_core.handlers._ipban_carve import IpBanCarveMixin
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


class IPBanManager(
    IpBanMigrationMixin, IpBanOperationsMixin, IpBanQueryMixin, IpBanCarveMixin
):
    LOCAL_CACHE_TTL_CAP_SECONDS = 3600
    MAX_LOCAL_BANS = DEFAULT_MAX_LOCAL_BANS
    _EVICTION_LOG_EVERY = 100

    _instance: "IPBanManager | None" = None
    banned_ips: MutableMapping[str, float]
    banned_networks: list[tuple[_Network, float]]
    refused_ban_reported_until: dict[str, float]
    evictions_count: int
    evicted_to_report: tuple[str, float] | None
    logger: logging.Logger
    config: Any = None
    redis_handler: Any = None
    agent_handler: Any = None

    def __new__(cls: type["IPBanManager"]) -> "IPBanManager":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance.evictions_count = 0
            cls._instance.logger = logging.getLogger("guard_core.handlers.ipban")
            cls._instance.banned_ips = _BanStore(
                maxsize=cls.MAX_LOCAL_BANS, on_evict=cls._instance._on_eviction
            )
            cls._instance.evicted_to_report = None
            cls._instance.banned_networks = []
            cls._instance.refused_ban_reported_until = {}
            cls._instance.rule_exempt_networks = ()
            cls._instance.redis_handler = None
            cls._instance.agent_handler = None
        return cls._instance

    def set_capacity(self, entries: int) -> None:
        if isinstance(self.banned_ips, _BanStore):
            self.banned_ips.resize(entries)

    def _on_eviction(self, *evicted: Any) -> None:
        self.evictions_count += 1
        if self.evictions_count == 1 or (
            self.evictions_count % self._EVICTION_LOG_EVERY == 0
        ):
            self.logger.warning(
                "IP ban cache full; %d entries evicted (silent overflow); use "
                "Redis to keep a large number of bans",
                self.evictions_count,
            )
            if evicted:
                self.evicted_to_report = (evicted[0], evicted[1])


ip_ban_manager = IPBanManager()


async def reset_global_state() -> None:
    global ip_ban_manager
    manager = IPBanManager()
    manager.banned_ips.clear()
    manager.banned_networks = []
    manager.refused_ban_reported_until = {}
    manager.rule_exempt_networks = ()
    manager.evictions_count = 0
    manager.evicted_to_report = None
    manager.redis_handler = None
    manager.agent_handler = None
    ip_ban_manager = manager
