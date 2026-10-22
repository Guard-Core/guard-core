import ipaddress
import logging
import time
from collections.abc import MutableMapping
from typing import Any

from guard_core.sync._utils.ip_extraction import (
    MALFORMED_FORWARDED_FOR_PREFIX,
    _canonicalize_ip,
    _client_identity,
    _parsed_ip_or_none,
)
from guard_core.sync._utils.whitelist_match import most_specific_whitelist_entry
from guard_core.sync.handlers._ipban_cache import _Network
from guard_core.sync.handlers._ipban_events import IpBanEventMixin
from guard_core.sync.handlers._ipban_rule_exempt import IpBanRuleExemptionMixin
from guard_core.sync.handlers._ipban_version import (
    _VERSION_PAIR,
    IpBanVersionMixin,
)

_DEFAULT_IPV6_PREFIX_LENGTH = 64


class IpBanLookupMixin(IpBanVersionMixin, IpBanEventMixin, IpBanRuleExemptionMixin):
    banned_ips: MutableMapping[str, float]
    banned_networks: list[tuple[_Network, float]]
    redis_handler: Any = None
    config: Any = None
    logger: logging.Logger

    def _grouped_identity_of(self, ip: str, config: Any) -> str | None:
        if ":" not in ip:
            return None
        prefix_length = self._prefix_length(config)
        identity = _client_identity(ip, prefix_length)
        whitelist = getattr(config, "whitelist", None)
        if identity == ip or not whitelist:
            return identity if identity != ip else None
        entry = most_specific_whitelist_entry(ipaddress.ip_address(ip), whitelist)
        return _client_identity(ip, prefix_length, entry) if entry else identity

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

    def _check_redis_keys(
        self,
        ip: str,
        identity: str | None,
        now: float,
        addr: ipaddress.IPv4Address | ipaddress.IPv6Address | None = None,
    ) -> bool:
        namespaces = [("banned_ips", ip)]
        if identity is not None:
            namespaces.append(("banned_identities", identity))
        values = self.redis_handler.get_many([*namespaces, _VERSION_PAIR])
        if self._version_moved(values.pop(), now):
            self._reload_operator_networks()
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
                self.redis_handler.delete(namespace, key)
        if self.agent_handler:
            self._report_evictions()
        return banned

    def _local_lookup(
        self, ip: str, config: Any, now: float
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
                return identity, None if self.redis_handler else False
            return identity, True
        return identity, None

    def _prefix_length(self, config: Any) -> int:
        configured = getattr(config, "ipv6_prefix_length", None)
        return configured or _DEFAULT_IPV6_PREFIX_LENGTH

    def _cached_positive_survives(self, now: float) -> bool:
        if not self._version_recheck_due(now):
            return True
        return self._positive_survives_recheck(now)

    def _operator_ban_holds(
        self, addr: ipaddress.IPv4Address | ipaddress.IPv6Address, now: float
    ) -> bool:
        if self._cached_positive_survives(now):
            return True
        return self._operator_networks is not None and self._operator_networks.covers(
            addr, now
        )

    def deciding_ban_entry(self, ip: str) -> tuple[str, float] | None:
        """The ban entry that answers ``ip``, as ``(namespace:key, expiry)``,
        read from what this process holds, in the order the lookup tries it:
        the address, its grouped identity, a local network, then an operator
        network read back from Redis. ``None`` when nothing live covers it."""
        ip = _canonicalize_ip(ip)
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

    def is_ip_banned(self, ip: str) -> bool:
        return self._is_ip_banned_under(ip, self.config)

    def _is_ip_banned_under(self, ip: str, config: Any) -> bool:
        """The ban lookup with the identity prefix and whitelist taken from
        ``config``: a caller outside the pipeline (the out-of-band rate-limit
        primitive) passes its own config without touching the manager's."""
        ip = _canonicalize_ip(ip)
        now = time.time()
        identity, verdict = self._local_lookup(ip, config, now)
        if verdict is False:
            return False
        if verdict is True and self._cached_positive_survives(now):
            return True

        addr = _parsed_ip_or_none(ip)
        if addr is None:
            return self._malformed_identity_banned(ip, now)

        if self._check_network_cache(addr, now):
            return True
        if not self.redis_handler:
            return False
        operator_networks = self._operator_networks
        if (
            operator_networks is None or operator_networks.has_networks
        ) and self._operator_networks_ban(addr, now):
            return True
        return self._check_redis_keys(ip, identity, now, addr)

    def _operator_networks_ban(
        self, addr: ipaddress.IPv4Address | ipaddress.IPv6Address, now: float
    ) -> bool:
        if self._operator_networks is None:
            self._reload_operator_networks()
        networks = self._operator_networks
        return (
            networks is not None
            and networks.covers(addr, now)
            and self._operator_ban_holds(addr, now)
        )

    def _malformed_identity_banned(self, ip: str, now: float) -> bool:
        if ip.startswith(MALFORMED_FORWARDED_FOR_PREFIX) and self.redis_handler:
            return self._check_redis_keys(ip, None, now)
        return False
