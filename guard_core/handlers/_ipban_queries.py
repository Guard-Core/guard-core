import ipaddress
import time
from typing import Any

from cachetools import TTLCache

from guard_core.handlers._ipban_cache import _Network
from guard_core.handlers._ipban_events import IpBanEventMixin
from guard_core.handlers._ipban_rule_exempt import IpBanRuleExemptionMixin
from guard_core.utils import _canonicalize_ip


def _network_inside(candidate: _Network, network: _Network) -> bool:
    return (
        candidate.version == network.version
        and candidate.network_address in network
        and candidate.broadcast_address in network
    )


def _address_inside(ip: str, network: _Network) -> bool:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return address.version == network.version and address in network


def _member_inside(namespace: str, member: str, network: _Network) -> bool:
    if namespace == "banned_ips":
        return _address_inside(member, network)
    return _network_inside(ipaddress.ip_network(member, strict=False), network)


class IpBanQueryMixin(IpBanEventMixin, IpBanRuleExemptionMixin):
    banned_ips: TTLCache
    banned_networks: list[tuple[_Network, float]]
    redis_handler: Any = None

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

    async def _check_redis_exact(self, ip: str, current_time: float) -> bool:
        expiry = await self.redis_handler.get_key("banned_ips", ip)
        if not expiry:
            return False
        expiry_time = float(expiry)
        if current_time <= expiry_time:
            self.banned_ips[ip] = expiry_time
            return True
        await self.redis_handler.delete("banned_ips", ip)
        return False

    def _purge_banned_ip(self, ip: str) -> None:
        try:
            del self.banned_ips[ip]
        except KeyError:
            return

    async def is_ip_banned(self, ip: str) -> bool:
        ip = _canonicalize_ip(ip)
        if self.rule_exempt_networks and self._is_rule_exempt_ip(ip):
            return False
        current_time = time.time()

        expiry = self.banned_ips.get(ip)
        if expiry is not None:
            if current_time > expiry:
                self._purge_banned_ip(ip)
                return False
            return True

        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False

        if self._check_network_cache(addr, current_time):
            return True

        if self.redis_handler:
            return await self._check_redis_exact(ip, current_time)

        return False

    async def _unban_cidr(self, cidr: str) -> None:
        network = ipaddress.ip_network(cidr, strict=False)
        self.banned_networks = [
            (banned, expiry)
            for banned, expiry in self.banned_networks
            if banned != network
        ]
        if self.redis_handler:
            await self.redis_handler.delete("banned_networks", str(network))

    async def unban_inside(self, entry: str) -> None:
        network = ipaddress.ip_network(entry, strict=False)
        self.banned_networks = [
            (banned, expiry)
            for banned, expiry in self.banned_networks
            if not _network_inside(banned, network)
        ]
        for ip in [ip for ip in self.banned_ips if _address_inside(ip, network)]:
            self._purge_banned_ip(ip)
        if self.redis_handler:
            await self._unban_inside_redis(network)

    async def _unban_inside_redis(self, network: _Network) -> None:
        for namespace in ("banned_ips", "banned_networks"):
            keys = await self.redis_handler.keys(f"{namespace}:*") or []
            for key in keys:
                member = key.split(f"{namespace}:", 1)[1]
                if _member_inside(namespace, member, network):
                    await self.redis_handler.delete(namespace, member)

    async def unban_ip(self, ip: str) -> None:
        if "/" in ip:
            await self._unban_cidr(ip)
            return
        ip = _canonicalize_ip(ip)
        self._purge_banned_ip(ip)

        if self.redis_handler:
            await self.redis_handler.delete("banned_ips", ip)

        if self.agent_handler:
            await self._send_unban_event(ip)

    async def reset(self) -> None:
        self.banned_ips.clear()
        self.banned_networks.clear()
        if self.redis_handler:
            async with self.redis_handler.get_connection() as conn:
                keys = await conn.keys(
                    f"{self.redis_handler.config.redis_prefix}banned_ips:*"
                )
                if keys:
                    await conn.delete(*keys)
