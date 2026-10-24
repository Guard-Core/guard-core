import logging
from collections.abc import MutableMapping
from typing import Any

from guard_core.sync._utils.app_managers import hold_for_app, redis_prefixes_differ
from guard_core.sync._utils.config_registry import ConfigHandlerRegistry
from guard_core.sync.handlers._ipban_bans import (
    _LOOPBACK_NETWORKS,
    IpBanOperationsMixin,
)
from guard_core.sync.handlers._ipban_cache import (
    DEFAULT_MAX_LOCAL_BANS,
    _BanStore,
    _Network,
    _ObservableTTLCache,
)
from guard_core.sync.handlers._ipban_carve import IpBanCarveMixin
from guard_core.sync.handlers._ipban_migration import (
    _BANNED_IPS_NAMESPACE,
    IpBanMigrationMixin,
    _close_if_unusable,
)
from guard_core.sync.handlers._ipban_queries import IpBanQueryMixin
from guard_core.sync.utils import _canonicalize_ip

__all__ = [
    "IPBanManager",
    "_BANNED_IPS_NAMESPACE",
    "_LOOPBACK_NETWORKS",
    "_Network",
    "_ObservableTTLCache",
    "_canonicalize_ip",
    "_close_if_unusable",
    "ip_ban_manager",
    "ip_ban_manager_for",
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
    recidive_history: dict[str, tuple[int, float]]
    evictions_count: int
    evicted_to_report: list[tuple[str, float, int]]
    logger: logging.Logger
    config: Any = None
    redis_handler: Any = None
    agent_handler: Any = None

    def __new__(cls: type["IPBanManager"]) -> "IPBanManager":
        if cls._instance is None:
            cls._instance = cls._fresh()
        return cls._instance

    @classmethod
    def _fresh(cls: type["IPBanManager"]) -> "IPBanManager":
        instance = super().__new__(cls)
        instance.evictions_count = 0
        instance.logger = logging.getLogger("guard_core.sync.handlers.ipban")
        instance.banned_ips = _BanStore(
            maxsize=cls.MAX_LOCAL_BANS, on_evict=instance._on_eviction
        )
        instance.evicted_to_report = []
        instance.banned_networks = []
        instance.refused_ban_reported_until = {}
        instance.recidive_history = {}
        instance.rule_exempt_networks = ()
        instance._rule_owned_expiries = {}
        instance._rule_owner_answers = {}
        instance._rule_floor_expiries = {}
        instance._foreign_network_expiries = {}
        instance.redis_handler = None
        instance.agent_handler = None
        return instance

    def set_capacity(self, entries: int) -> None:
        """Resize the store. The memory-only bans it evicts are queued in
        ``evicted_to_report`` and sent by the next ban or Redis-hit insert."""
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
        store = self.banned_ips
        if (
            evicted
            and self.agent_handler
            and isinstance(store, _BanStore)
            and store.is_memory_only(evicted[0])
        ):
            self.evicted_to_report.append(
                (evicted[0], evicted[1], self.evictions_count)
            )


ip_ban_manager = IPBanManager()

_APP_BAN_MANAGERS = ConfigHandlerRegistry()
_DEFAULT_APPS = ConfigHandlerRegistry()
_BAN_KIND = "ipban"


def ip_ban_manager_for(
    config: Any, bind: bool = False, unbound: IPBanManager | None = None
) -> IPBanManager:
    """The ban manager of the app built from config.

    An app that uses Redis under its own ``redis_prefix`` gets a manager of its
    own when the module-level ``ip_ban_manager`` serves another app's prefix, so
    two apps never share bans. Anything else shares ``ip_ban_manager`` as before.
    ``bind`` (the app's handler set) configures it; the checks only look it up.
    A config no app was bound to gets ``unbound``, else ``ip_ban_manager``.
    """
    own: IPBanManager | None = _APP_BAN_MANAGERS.lookup(config, _BAN_KIND)
    if own is not None:
        return own
    if not bind:
        if _DEFAULT_APPS.lookup(config, _BAN_KIND) is None and unbound is not None:
            return unbound
        return ip_ban_manager
    served = ip_ban_manager.config
    manager = ip_ban_manager
    if _DEFAULT_APPS.lookup(served, _BAN_KIND) is not None and redis_prefixes_differ(
        served, config
    ):
        manager = IPBanManager._fresh()
        _APP_BAN_MANAGERS.register(config, manager, _BAN_KIND)
        hold_for_app(config, _BAN_KIND, manager)
    else:
        _DEFAULT_APPS.register(config, manager, _BAN_KIND)
    manager.config = config
    return manager


def _forget_app_binding(manager: IPBanManager) -> None:
    if manager.config is not None:
        _DEFAULT_APPS.drop(manager.config, _BAN_KIND)


def reset_global_state() -> None:
    global ip_ban_manager
    manager = IPBanManager()
    manager.banned_ips.clear()
    manager.banned_networks = []
    manager.refused_ban_reported_until = {}
    manager.recidive_history = {}
    manager.rule_exempt_networks = ()
    manager._rule_owned_expiries = {}
    manager._rule_owner_answers = {}
    manager._rule_floor_expiries = {}
    manager._foreign_network_expiries = {}
    manager.evictions_count = 0
    manager.evicted_to_report = []
    manager.redis_handler = None
    manager.agent_handler = None
    _forget_app_binding(manager)
    ip_ban_manager = manager
