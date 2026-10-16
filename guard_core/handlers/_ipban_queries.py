import asyncio
import ipaddress
import logging
import time
from collections.abc import Iterable
from typing import Any

from cachetools import TTLCache

from guard_core.handlers._ipban_cache import _Network
from guard_core.handlers._ipban_coverage import NetworkCoverage
from guard_core.handlers._ipban_events import IpBanEventMixin
from guard_core.handlers._ipban_rule_exempt import IpBanRuleExemptionMixin
from guard_core.utils import _canonicalize_ip

_BATCH = 2000


def _member_covered(namespace: str, member: str, coverage: NetworkCoverage) -> bool:
    if namespace == "banned_ips":
        return coverage.covers_address(member)
    try:
        return coverage.covers_network(ipaddress.ip_network(member, strict=False))
    except ValueError:
        return False


class IpBanQueryMixin(IpBanEventMixin, IpBanRuleExemptionMixin):
    banned_ips: TTLCache
    banned_networks: list[tuple[_Network, float]]
    redis_handler: Any = None
    logger: logging.Logger

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

    async def unban_inside(self, entries: Iterable[str]) -> None:
        networks = [ipaddress.ip_network(entry, strict=False) for entry in entries]
        if not networks:
            return
        coverage = NetworkCoverage(networks)
        removed = await self._unban_memory_inside(coverage)
        if self.redis_handler:
            removed.extend(await self._unban_redis_inside(coverage))
        if self.agent_handler:
            for member in dict.fromkeys(removed):
                await self._send_unban_event(member)

    async def _unban_memory_inside(self, coverage: NetworkCoverage) -> list[str]:
        removed: list[str] = []
        kept: list[tuple[_Network, float]] = []
        for banned, expiry in self.banned_networks:
            if coverage.covers_network(banned):
                removed.append(str(banned))
            else:
                kept.append((banned, expiry))
        self.banned_networks = kept
        keys = list(self.banned_ips)
        for start in range(0, len(keys), _BATCH):
            for ip in keys[start : start + _BATCH]:
                if coverage.covers_address(ip):
                    self._purge_banned_ip(ip)
                    removed.append(ip)
            await asyncio.sleep(0)
        return removed

    async def _unban_redis_inside(self, coverage: NetworkCoverage) -> list[str]:
        removed: list[str] = []
        prefix = self.redis_handler.config.redis_prefix
        try:
            async with self.redis_handler.get_connection() as conn:
                for namespace in ("banned_ips", "banned_networks"):
                    stem = f"{prefix}{namespace}:"
                    batch: list[str] = []
                    async for key in conn.scan_iter(match=f"{stem}*", count=_BATCH):
                        member = key[len(stem) :]
                        if _member_covered(namespace, member, coverage):
                            batch.append(key)
                            removed.append(member)
                        if len(batch) >= _BATCH:
                            await conn.delete(*batch)
                            batch.clear()
                            await asyncio.sleep(0)
                    if batch:
                        await conn.delete(*batch)
        except Exception as e:
            self.logger.warning("Redis unban of whitelisted ranges failed: %s", e)
        return removed

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
