import ipaddress
import logging
import time
from collections.abc import MutableMapping
from typing import Any

from guard_core._utils.ip_extraction import (
    MALFORMED_FORWARDED_FOR_PREFIX,
    _canonicalize_ip,
    _client_identity,
)
from guard_core.handlers._ipban_cache import _Network
from guard_core.handlers._ipban_rule_exempt import IpBanRuleExemptionMixin

_DEFAULT_IPV6_PREFIX_LENGTH = 64


class IpBanLookupMixin(IpBanRuleExemptionMixin):
    banned_ips: MutableMapping[str, float]
    banned_networks: list[tuple[_Network, float]]
    redis_handler: Any = None
    config: Any = None
    logger: logging.Logger

    def _grouped_identity_of(self, ip: str) -> str | None:
        if ":" not in ip:
            return None
        prefix_length = getattr(self.config, "ipv6_prefix_length", None)
        identity = _client_identity(ip, prefix_length or _DEFAULT_IPV6_PREFIX_LENGTH)
        return identity if identity != ip else None

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

    def _local_ban_state(self, key: str, now: float) -> bool | None:
        expiry = self.banned_ips.get(key)
        if expiry is None:
            return None
        if now > expiry:
            self._purge_banned_ip(key)
            return False
        return True

    async def _check_redis_keys(
        self, namespaces: list[tuple[str, str]], now: float
    ) -> bool:
        if len(namespaces) == 1:
            values = [await self.redis_handler.get_key(*namespaces[0])]
        else:
            values = await self.redis_handler.get_many(namespaces)
        banned = False
        for (namespace, key), value in zip(namespaces, values, strict=True):
            if not value:
                continue
            expiry_time = float(value)
            if now <= expiry_time:
                self.banned_ips[key] = expiry_time
                banned = True
            else:
                await self.redis_handler.delete(namespace, key)
        return banned

    async def is_ip_banned(self, ip: str) -> bool:
        ip = _canonicalize_ip(ip)
        if self.rule_exempt_networks and self._is_rule_exempt_ip(ip):
            return False
        now = time.time()
        identity = self._grouped_identity_of(ip)

        state = self._local_ban_state(ip, now)
        if state is not None:
            return state
        if identity is not None:
            state = self._local_ban_state(identity, now)
            if state is not None:
                return state

        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return await self._malformed_identity_banned(ip, now)

        if self._check_network_cache(addr, now):
            return True

        if not self.redis_handler:
            return False
        keys = [("banned_ips", ip)]
        if identity is not None:
            keys.append(("banned_identities", identity))
        return await self._check_redis_keys(keys, now)

    async def _malformed_identity_banned(self, ip: str, now: float) -> bool:
        if ip.startswith(MALFORMED_FORWARDED_FOR_PREFIX) and self.redis_handler:
            return await self._check_redis_keys([("banned_ips", ip)], now)
        return False
