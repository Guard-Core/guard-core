import ipaddress
import logging
import time
from collections.abc import Awaitable, Callable, MutableMapping
from typing import TYPE_CHECKING, NamedTuple

from guard_core._utils.app_scope import (
    SHARED_BY_APPS,
    _current_app_scope,
    app_scope_of,
    in_app_scope,
)
from guard_core._utils.ip_extraction import (
    MALFORMED_FORWARDED_FOR_PREFIX,
    _canonicalize_ip,
    _client_identity,
    _parsed_ip_or_none,
)
from guard_core._utils.nat64 import nat64_table_of
from guard_core._utils.whitelist_match import most_specific_whitelist_entry
from guard_core.handlers._ipban_cache import _Network
from guard_core.handlers._ipban_events import IpBanEventMixin
from guard_core.handlers._ipban_rule_exempt import IpBanRuleExemptionMixin
from guard_core.handlers._ipban_version import (
    _VERSION_PAIR,
    IpBanVersionMixin,
)
from guard_core.protocols.redis_protocol import RedisHandlerProtocol

if TYPE_CHECKING:
    from guard_core.core.checks._shared_strikes import FusedStrike
    from guard_core.models import SecurityConfig

_DEFAULT_IPV6_PREFIX_LENGTH = 64
# RedisBanStrikeMixin, not a member of RedisHandlerProtocol: a handler without it
# fails here, as it did before.
_FUSED_BAN_READ = "get_bans_and_record_strike"


class PendingKeysRead(NamedTuple):
    """A ban lookup that only the Redis ban keys can still decide."""

    ip: str
    identity: str | None
    addr: ipaddress.IPv4Address | ipaddress.IPv6Address


class IpBanLookupMixin(IpBanVersionMixin, IpBanEventMixin, IpBanRuleExemptionMixin):
    banned_ips: MutableMapping[str, float]
    banned_networks: list[tuple[_Network, float]]
    redis_handler: RedisHandlerProtocol | None = None
    config: "SecurityConfig | None" = None
    logger: logging.Logger
    _is_ip_banned_across_sharing_apps: Callable[[str], Awaitable[bool]]
    _ban_stands_for: Callable[[str, "SecurityConfig | None"], bool]

    def _redis_or_raise(self) -> RedisHandlerProtocol:
        redis_handler = self.redis_handler
        if redis_handler is None:
            raise RuntimeError("the ban lookup needs the Redis handler it read from")
        return redis_handler

    def _grouped_identity_of(
        self, ip: str, config: "SecurityConfig | None"
    ) -> str | None:
        if ":" not in ip:
            return None
        prefix_length = self._prefix_length(config)
        nat64 = nat64_table_of(config)
        identity = _client_identity(ip, prefix_length, None, nat64)
        whitelist = getattr(config, "whitelist", None)
        if identity == ip or not whitelist:
            return identity if identity != ip else None
        entry = most_specific_whitelist_entry(
            ipaddress.ip_address(ip), whitelist, nat64
        )
        return _client_identity(ip, prefix_length, entry, nat64) if entry else identity

    def _check_network_cache(
        self, addr: ipaddress.IPv4Address | ipaddress.IPv6Address, now: float
    ) -> bool:
        active: list[tuple[_Network, float]] = []
        hit = False
        for network, expiry in self.banned_networks:
            if expiry <= now:
                continue
            active.append((network, expiry))
            if not hit and addr.version == network.version and addr in network:
                hit = True
        self.banned_networks = active
        return hit

    def _purge_banned_ip(self, ip: str) -> None:
        try:
            del self.banned_ips[ip]
        except KeyError:
            return

    async def _check_redis_keys(
        self,
        ip: str,
        identity: str | None,
        now: float,
        addr: ipaddress.IPv4Address | ipaddress.IPv6Address | None = None,
        fused_strike: Callable[[], Awaitable["FusedStrike | None"]] | None = None,
    ) -> bool:
        namespaces = [("banned_ips", ip)]
        if identity is not None:
            namespaces.append(("banned_identities", identity))
        redis_handler = self.redis_handler
        if redis_handler is None:
            return False
        strike = await fused_strike() if fused_strike is not None else None
        if strike is None:
            values: list[str | bytes | float | None] = [
                *await redis_handler.get_many([*namespaces, _VERSION_PAIR])
            ]
        else:
            fused_read = getattr(redis_handler, _FUSED_BAN_READ)
            values, recorded = await fused_read(
                namespaces,
                _VERSION_PAIR,
                self._ban_version_seen,
                now,
                strike.client_ip,
                strike.categories,
                now,
                now - strike.window_seconds,
                strike.window_seconds,
                strike.cap,
            )
            strike.record(recorded)
        return await self.decide_from_ban_values(namespaces, values, now, addr)

    def ban_key_pairs(self, read: PendingKeysRead) -> list[tuple[str, str]]:
        pairs = [("banned_ips", read.ip)]
        if read.identity is not None:
            pairs.append(("banned_identities", read.identity))
        return pairs

    async def decide_from_ban_values(
        self,
        namespaces: list[tuple[str, str]],
        values: list[str | bytes | float | None],
        now: float,
        addr: ipaddress.IPv4Address | ipaddress.IPv6Address | None = None,
    ) -> bool:
        """The ban verdict of the values read for ``namespaces`` plus, last, the
        ban version, by whatever round trip read them."""
        if self._version_moved(values.pop(), now):
            await self._reload_operator_networks(self._redis_or_raise())
            networks = self._operator_networks
            if addr is not None and networks is not None and networks.covers(addr, now):
                return True
        banned = False
        for (namespace, key), value in zip(namespaces, values, strict=True):
            if not value:
                continue
            expiry_time = float(value)
            if now <= expiry_time:
                self.banned_ips[key] = self._local_expiry(expiry_time)
                banned = True
            else:
                await self._redis_or_raise().delete(namespace, key)
        if self.agent_handler:
            await self._report_evictions(self.agent_handler)
        return banned

    def _local_lookup(
        self, ip: str, config: "SecurityConfig | None", now: float
    ) -> tuple[str | None, bool | None]:
        if self.rule_exempt_networks and self._is_rule_exempt_ip(ip):
            return None, False
        identity = self._grouped_identity_of(ip, config) if ":" in ip else None
        for key in (ip, identity):
            if key is None:
                continue
            expiry = self.banned_ips.get(key)
            if expiry is None:
                continue
            if now > expiry:
                self._purge_banned_ip(key)
                continue
            return identity, True
        return identity, None

    def _prefix_length(self, config: "SecurityConfig | None") -> int:
        configured = getattr(config, "ipv6_prefix_length", None)
        return configured or _DEFAULT_IPV6_PREFIX_LENGTH

    async def _cached_positive_survives(self, now: float) -> bool:
        redis_handler = self.redis_handler
        if not redis_handler or not self._version_recheck_due(now):
            return True
        return await self._positive_survives_recheck(redis_handler, now)

    async def _operator_ban_holds(
        self, addr: ipaddress.IPv4Address | ipaddress.IPv6Address, now: float
    ) -> bool:
        if await self._cached_positive_survives(now):
            return True
        return self._operator_networks is not None and self._operator_networks.covers(
            addr, now
        )

    def deciding_ban_entry(self, ip: str) -> tuple[str, float] | None:
        """The ban entry that answers ``ip``, as ``(namespace:key, expiry)``,
        read from what this process holds, in the order the lookup tries it:
        the address, its grouped identity, a local network, then an operator
        network read back from Redis. ``None`` when nothing live covers it."""
        ip = _canonicalize_ip(ip, nat64_table_of(self.config))
        now = time.time()
        identity = self._grouped_identity_of(ip, self.config) if ":" in ip else None
        held = self._deciding_keyed_entry(ip, identity, now)
        if held is not None:
            return held
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        return self._deciding_network_entry(addr, now)

    def _deciding_keyed_entry(
        self, ip: str, identity: str | None, now: float
    ) -> tuple[str, float] | None:
        for namespace, key in (("banned_ips", ip), ("banned_identities", identity)):
            expiry = self.banned_ips.get(key) if key is not None else None
            if expiry is not None and expiry > now:
                return f"{namespace}:{key}", expiry
        return None

    def _deciding_network_entry(
        self, addr: ipaddress.IPv4Address | ipaddress.IPv6Address, now: float
    ) -> tuple[str, float] | None:
        for network, expiry in self.banned_networks:
            if expiry > now and addr.version == network.version and addr in network:
                return f"banned_networks:{network}", expiry
        operator = self._operator_networks
        found = operator.covering(addr, now) if operator is not None else None
        return None if found is None else (f"banned_networks:{found[0]}", found[1])

    async def is_ip_banned(
        self,
        ip: str,
        fused_strike: Callable[[], Awaitable["FusedStrike | None"]] | None = None,
        defer_read: Callable[[PendingKeysRead], Awaitable[bool]] | None = None,
        config: "SecurityConfig | None" = None,
    ) -> bool:
        """The ban lookup. ``defer_read`` may take over the Redis ban keys read
        (return ``True``): the caller then holds the read and the answer here is
        ``False`` until it resolves it. ``config`` runs the lookup as that app."""
        if config is not None:
            with in_app_scope(app_scope_of(config)):
                return await self._is_ip_banned_under(
                    ip, config, fused_strike, defer_read
                )
        if _current_app_scope.get() is None and self.__dict__.get(SHARED_BY_APPS):
            return await self._is_ip_banned_across_sharing_apps(ip)
        return await self._is_ip_banned_under(ip, self.config, fused_strike, defer_read)

    async def _is_ip_banned_under(
        self,
        ip: str,
        config: "SecurityConfig | None",
        fused_strike: Callable[[], Awaitable["FusedStrike | None"]] | None = None,
        defer_read: Callable[[PendingKeysRead], Awaitable[bool]] | None = None,
    ) -> bool:
        """The ban lookup with the identity prefix and whitelist taken from
        ``config``: a caller outside the pipeline (the out-of-band rate-limit
        primitive) passes its own config without touching the manager's."""
        outcome = await self._ban_outcome_before_keys(ip, config)
        if not isinstance(outcome, PendingKeysRead):
            return outcome and self._ban_stands_for(ip, config)
        if defer_read is not None and await defer_read(outcome):
            return False
        return await self.finish_ban_check(outcome, fused_strike, config)

    async def begin_ban_check(self, ip: str) -> bool | PendingKeysRead:
        """What the lookup decides without the Redis ban keys: ``True`` or
        ``False``, or the read of those keys, left for ``finish_ban_check``."""
        outcome = await self._ban_outcome_before_keys(ip, self.config)
        if outcome is True:
            return self._ban_stands_for(ip, self.config)
        return outcome

    async def finish_ban_check(
        self,
        read: PendingKeysRead,
        fused_strike: Callable[[], Awaitable["FusedStrike | None"]] | None = None,
        config: "SecurityConfig | None" = None,
    ) -> bool:
        banned = await self._check_redis_keys(
            read.ip, read.identity, time.time(), read.addr, fused_strike
        )
        return banned and self._ban_stands_for(
            read.ip, self.config if config is None else config
        )

    async def _ban_outcome_before_keys(
        self, ip: str, config: "SecurityConfig | None"
    ) -> bool | PendingKeysRead:
        ip = _canonicalize_ip(
            ip, nat64_table_of(self.config if config is None else config)
        )
        now = time.time()
        identity, verdict = self._local_lookup(ip, config, now)
        if verdict is False:
            return False
        if verdict is True and (
            await self._cached_positive_survives(now)
            or self._local_lookup(ip, config, now)[1] is True
        ):
            return True

        addr = _parsed_ip_or_none(ip)
        if addr is None:
            return await self._malformed_identity_banned(ip, now)

        if self._check_network_cache(addr, now):
            return True
        if not self.redis_handler:
            return False
        return await self._outcome_before_ban_keys_read(ip, identity, addr, now)

    async def _outcome_before_ban_keys_read(
        self,
        ip: str,
        identity: str | None,
        addr: ipaddress.IPv4Address | ipaddress.IPv6Address,
        now: float,
    ) -> bool | PendingKeysRead:
        operator_networks = self._operator_networks
        if (
            operator_networks is None or operator_networks.has_networks
        ) and await self._operator_networks_ban(addr, now):
            return True
        return PendingKeysRead(ip, identity, addr)

    async def _operator_networks_ban(
        self, addr: ipaddress.IPv4Address | ipaddress.IPv6Address, now: float
    ) -> bool:
        if self._operator_networks is None:
            await self._reload_operator_networks(self._redis_or_raise())
        networks = self._operator_networks
        return (
            networks is not None
            and networks.covers(addr, now)
            and await self._operator_ban_holds(addr, now)
        )

    async def _malformed_identity_banned(self, ip: str, now: float) -> bool:
        if ip.startswith(MALFORMED_FORWARDED_FOR_PREFIX) and self.redis_handler:
            return await self._check_redis_keys(ip, None, now)
        return False
