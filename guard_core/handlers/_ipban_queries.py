import asyncio
import ipaddress
import logging
import time
from collections.abc import Callable, Iterable, MutableMapping
from typing import Any

from guard_core._utils.ip_extraction import MALFORMED_FORWARDED_FOR_PREFIX
from guard_core.handlers._ipban_cache import _Network
from guard_core.handlers._ipban_coverage import NetworkCoverage
from guard_core.handlers._ipban_events import IpBanEventMixin
from guard_core.handlers._ipban_rule_exempt import IpBanRuleExemptionMixin
from guard_core.handlers.redis_handler import scan_unlink
from guard_core.utils import _canonicalize_ip

_BATCH = 2000
_MEMORY_BATCH = 1000
_EVENT_BATCH = 100
_STRIKE_PATTERNS = ("rate_limit:violations:*", "detection:strikes*")


def _member_covered(namespace: str, member: str, coverage: NetworkCoverage) -> bool:
    if namespace == "banned_ips":
        return coverage.covers_address(member)
    try:
        return coverage.covers_network(ipaddress.ip_network(member, strict=False))
    except ValueError:
        return False


def _strike_key_inside(coverage: NetworkCoverage, stem: str) -> Callable[[str], bool]:
    def inside(key: str) -> bool:
        return coverage.covers_address(key[len(stem) :].split("|", 1)[0])

    return inside


class IpBanQueryMixin(IpBanEventMixin, IpBanRuleExemptionMixin):
    banned_ips: MutableMapping[str, float]
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
            if ip.startswith(MALFORMED_FORWARDED_FOR_PREFIX) and self.redis_handler:
                return await self._check_redis_exact(ip, current_time)
            return False

        if self._check_network_cache(addr, current_time):
            return True

        if self.redis_handler:
            return await self._check_redis_exact(ip, current_time)

        return False

    async def _unban_cidr(self, cidr: str, reason: str) -> None:
        network = ipaddress.ip_network(cidr, strict=False)
        self.banned_networks = [
            (banned, expiry)
            for banned, expiry in self.banned_networks
            if banned != network
        ]
        if self.redis_handler:
            await self.redis_handler.delete("banned_networks", str(network))
        if self.agent_handler:
            await self._send_unban_event(str(network), reason)

    async def unban_inside(self, entries: Iterable[str]) -> None:
        networks = [ipaddress.ip_network(entry, strict=False) for entry in entries]
        if not networks:
            return
        coverage = NetworkCoverage(networks)
        removed = await self._unban_memory_inside(coverage)
        if self.redis_handler:
            removed.extend(await self._unban_redis_inside(coverage))
        members = list(dict.fromkeys(removed))
        await self._forget_strikes_of(members)
        if self.agent_handler:
            await self._send_unban_events(members, "dynamic_rule_whitelist")

    async def _forget_strikes_of(self, members: list[str]) -> None:
        for start in range(0, len(members), _EVENT_BATCH):
            for member in members[start : start + _EVENT_BATCH]:
                if "/" not in member:
                    await self._forget_strikes(member)
            await asyncio.sleep(0)

    async def _forget_strikes(self, ip: str, strict: bool = False) -> None:
        from guard_core.core.checks._strike_forget import forget_identity_strikes
        from guard_core.handlers.ratelimit_handler import (
            forget_by_ip_strikes,
            forget_shared_violations,
        )

        forget_identity_strikes(ip)
        forget_by_ip_strikes(ip)
        if not self.redis_handler:
            return
        try:
            await forget_shared_violations(self.redis_handler, ip)
            await self.redis_handler.forget_detection_strikes(ip)
        except Exception as e:
            if strict:
                raise
            self.logger.warning("Redis strikes of %s could not be cleared: %s", ip, e)

    async def forget_strikes_of_ip(self, ip: str, strict: bool = False) -> None:
        await self._forget_strikes(_canonicalize_ip(ip), strict)

    async def forget_strikes_inside(
        self, entries: Iterable[str], strict: bool = False
    ) -> None:
        networks = [ipaddress.ip_network(entry, strict=False) for entry in entries]
        if not networks:
            return
        coverage = NetworkCoverage(networks)
        from guard_core.core.checks._strike_forget import forget_identities_inside
        from guard_core.handlers.ratelimit_handler import forget_by_ip_strikes_inside

        forget_identities_inside(coverage.covers_address)
        forget_by_ip_strikes_inside(coverage.covers_address)
        if not self.redis_handler:
            return
        try:
            await self._unlink_strikes_inside(coverage)
        except Exception as e:
            if strict:
                raise
            self.logger.warning(
                "Redis strikes inside a range could not be cleared: %s", e
            )

    async def _unlink_strikes_inside(self, coverage: NetworkCoverage) -> None:
        prefix = self.redis_handler.config.redis_prefix
        async with self.redis_handler.get_connection() as conn:
            for stem in (
                f"{prefix}rate_limit:violations:",
                f"{prefix}detection:strikes:",
                f"{prefix}detection:strikes_index:",
            ):
                await scan_unlink(conn, f"{stem}*", _strike_key_inside(coverage, stem))

    async def _forget_all_strikes(self) -> None:
        from guard_core.core.checks._strike_forget import forget_all_strikes
        from guard_core.handlers.ratelimit_handler import clear_by_ip_strikes

        forget_all_strikes()
        clear_by_ip_strikes()
        if not self.redis_handler:
            return
        try:
            await self._unlink_prefixed(_STRIKE_PATTERNS)
        except Exception as e:
            self.logger.warning("Redis strikes could not be cleared: %s", e)

    async def _unlink_prefixed(self, patterns: Iterable[str]) -> None:
        prefix = self.redis_handler.config.redis_prefix
        async with self.redis_handler.get_connection() as conn:
            for pattern in patterns:
                await scan_unlink(conn, f"{prefix}{pattern}")

    async def _send_unban_events(self, members: list[str], reason: str) -> None:
        for start in range(0, len(members), _EVENT_BATCH):
            for member in members[start : start + _EVENT_BATCH]:
                await self._send_unban_event(member, reason)
            await asyncio.sleep(0)

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
        for start in range(0, len(keys), _MEMORY_BATCH):
            for ip in keys[start : start + _MEMORY_BATCH]:
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
                            await conn.unlink(*batch)
                            batch.clear()
                            await asyncio.sleep(0)
                    if batch:
                        await conn.unlink(*batch)
        except Exception as e:
            self.logger.warning("Redis unban of whitelisted ranges failed: %s", e)
        return removed

    async def unban_ip(self, ip: str, reason: str = "manual_unban") -> None:
        if "/" in ip:
            await self._unban_cidr(ip, reason)
            return
        ip = _canonicalize_ip(ip)
        self._purge_banned_ip(ip)

        if self.redis_handler:
            await self.redis_handler.delete("banned_ips", ip)

        await self._forget_strikes(ip)

        if self.agent_handler:
            await self._send_unban_event(ip, reason)

    async def reset(self) -> None:
        self.banned_ips.clear()
        self.banned_networks.clear()
        if self.redis_handler:
            await self._unlink_prefixed(("banned_ips:*", "banned_networks:*"))
        await self._forget_all_strikes()
