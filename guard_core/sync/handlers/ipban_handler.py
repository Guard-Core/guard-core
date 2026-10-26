import logging
from collections.abc import MutableMapping
from typing import TYPE_CHECKING

from guard_core.sync._utils.app_managers import AppManagers
from guard_core.sync._utils.app_scope import (
    ScopedAgentHandler,
    ScopedConfig,
    ScopedRedisHandler,
    ScopedRuleExemptNetworks,
)
from guard_core.sync.handlers._ipban_bans import _LOOPBACK_NETWORKS
from guard_core.sync.handlers._ipban_cache import (
    DEFAULT_MAX_LOCAL_BANS,
    _BanStore,
    _Network,
    _ObservableTTLCache,
)
from guard_core.sync.handlers._ipban_migration import (
    _BANNED_IPS_NAMESPACE,
    _close_if_unusable,
)
from guard_core.sync.handlers._ipban_sharing import IpBanSharedAppsMixin
from guard_core.sync.protocols.agent_protocol import SyncAgentHandlerProtocol
from guard_core.sync.protocols.redis_protocol import SyncRedisHandlerProtocol
from guard_core.sync.utils import _canonicalize_ip

if TYPE_CHECKING:
    from guard_core.models import SyncSecurityConfig

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


class IPBanManager(IpBanSharedAppsMixin):
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
    # At runtime each descriptor serves the slot from the app scope in force; the
    # type checker sees the plain slot the descriptor returns and accepts.
    if TYPE_CHECKING:
        config: SyncSecurityConfig | None
        redis_handler: SyncRedisHandlerProtocol | None
        agent_handler: SyncAgentHandlerProtocol | None
    else:
        config = ScopedConfig()
        redis_handler = ScopedRedisHandler()
        agent_handler = ScopedAgentHandler()
    rule_exempt_networks = ScopedRuleExemptNetworks()

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

    def _on_eviction(self, key: str | None = None, expiry: float = 0.0) -> None:
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
            key is not None
            and self.agent_handler
            and isinstance(store, _BanStore)
            and store.is_memory_only(key)
        ):
            self.evicted_to_report.append((key, expiry, self.evictions_count))


ip_ban_manager = IPBanManager()

_APP_BAN_MANAGERS: AppManagers[IPBanManager] = AppManagers(
    "ipban", warns_on_split_connection=True
)


def ip_ban_manager_for(
    config: "SyncSecurityConfig",
    bind: bool = False,
    unbound: IPBanManager | None = None,
) -> IPBanManager:
    """The ban manager of the app built from config.

    The module-level ``ip_ban_manager`` serves the first app and every app on its
    Redis prefix. Any other app (another prefix, or no Redis) gets a manager of
    its own, so two apps never share bans, and never moves the prefix the default
    serves. ``bind`` (the app's handler set) configures it; the checks only look
    it up. A config no app was bound to gets ``unbound``, else ``ip_ban_manager``.
    """
    if bind:
        manager = _APP_BAN_MANAGERS.bind(config, ip_ban_manager, IPBanManager._fresh)
        manager.config = config
        return manager
    own = _APP_BAN_MANAGERS.own(config)
    if own is not None:
        return own
    if unbound is not None and not _APP_BAN_MANAGERS.uses_default(config):
        return unbound
    return ip_ban_manager


def _forget_app_binding(manager: IPBanManager) -> None:
    _APP_BAN_MANAGERS.forget_default()


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
