import ipaddress
import logging
import time
from collections.abc import Callable, Iterable
from typing import Any

from cachetools import Cache, TTLCache

from guard_core.sync.handlers._ipban_cache import _Network
from guard_core.sync.handlers._ipban_coverage import NetworkCoverage
from guard_core.sync.handlers._ipban_events import IpBanEventMixin
from guard_core.sync.handlers._ipban_rule_exempt import IpBanRuleExemptionMixin
from guard_core.sync.handlers.redis_handler import scan_unlink
from guard_core.sync.utils import _canonicalize_ip

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

    def _check_redis_exact(self, ip: str, current_time: float) -> bool:
        expiry = self.redis_handler.get_key("banned_ips", ip)
        if not expiry:
            return False
        expiry_time = float(expiry)
        if current_time <= expiry_time:
            self.banned_ips[ip] = expiry_time
            return True
        self.redis_handler.delete("banned_ips", ip)
        return False

    def _purge_banned_ip(self, ip: str) -> None:
        try:
            del self.banned_ips[ip]
        except KeyError:
            return

    def is_ip_banned(self, ip: str) -> bool:
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
            return self._check_redis_exact(ip, current_time)

        return False

    def _unban_cidr(self, cidr: str) -> None:
        network = ipaddress.ip_network(cidr, strict=False)
        self.banned_networks = [
            (banned, expiry)
            for banned, expiry in self.banned_networks
            if banned != network
        ]
        if self.redis_handler:
            self.redis_handler.delete("banned_networks", str(network))

    def unban_inside(self, entries: Iterable[str]) -> None:
        networks = [ipaddress.ip_network(entry, strict=False) for entry in entries]
        if not networks:
            return
        coverage = NetworkCoverage(networks)
        removed = self._unban_memory_inside(coverage)
        if self.redis_handler:
            removed.extend(self._unban_redis_inside(coverage))
        members = list(dict.fromkeys(removed))
        self._forget_strikes_of(members)
        if self.agent_handler:
            self._send_unban_events(members)

    def _forget_strikes_of(self, members: list[str]) -> None:
        for start in range(0, len(members), _EVENT_BATCH):
            for member in members[start : start + _EVENT_BATCH]:
                if "/" not in member:
                    self._forget_strikes(member)
            time.sleep(0)

    def _forget_strikes(self, ip: str) -> None:
        from guard_core.sync.core.checks._strike_forget import forget_identity_strikes
        from guard_core.sync.handlers.ratelimit_handler import (
            forget_by_ip_strikes,
            forget_shared_violations,
        )

        forget_identity_strikes(ip)
        forget_by_ip_strikes(ip)
        if not self.redis_handler:
            return
        try:
            forget_shared_violations(self.redis_handler, ip)
            self.redis_handler.forget_detection_strikes(ip)
        except Exception as e:
            self.logger.warning("Redis strikes of %s could not be cleared: %s", ip, e)

    def forget_strikes_inside(self, entries: Iterable[str]) -> None:
        networks = [ipaddress.ip_network(entry, strict=False) for entry in entries]
        if not networks:
            return
        coverage = NetworkCoverage(networks)
        from guard_core.sync.core.checks._strike_forget import forget_identities_inside
        from guard_core.sync.handlers.ratelimit_handler import (
            forget_by_ip_strikes_inside,
        )

        forget_identities_inside(coverage.covers_address)
        forget_by_ip_strikes_inside(coverage.covers_address)
        if not self.redis_handler:
            return
        try:
            self._unlink_strikes_inside(coverage)
        except Exception as e:
            self.logger.warning(
                "Redis strikes inside a range could not be cleared: %s", e
            )

    def _unlink_strikes_inside(self, coverage: NetworkCoverage) -> None:
        prefix = self.redis_handler.config.redis_prefix
        with self.redis_handler.get_connection() as conn:
            for stem in (
                f"{prefix}rate_limit:violations:",
                f"{prefix}detection:strikes:",
                f"{prefix}detection:strikes_index:",
            ):
                scan_unlink(conn, f"{stem}*", _strike_key_inside(coverage, stem))

    def _forget_all_strikes(self) -> None:
        from guard_core.sync.core.checks._strike_forget import forget_all_strikes
        from guard_core.sync.handlers.ratelimit_handler import clear_by_ip_strikes

        forget_all_strikes()
        clear_by_ip_strikes()
        if not self.redis_handler:
            return
        try:
            self._unlink_prefixed(_STRIKE_PATTERNS)
        except Exception as e:
            self.logger.warning("Redis strikes could not be cleared: %s", e)

    def _unlink_prefixed(self, patterns: Iterable[str]) -> None:
        prefix = self.redis_handler.config.redis_prefix
        with self.redis_handler.get_connection() as conn:
            for pattern in patterns:
                scan_unlink(conn, f"{prefix}{pattern}")

    def _send_unban_events(self, members: list[str]) -> None:
        for start in range(0, len(members), _EVENT_BATCH):
            for member in members[start : start + _EVENT_BATCH]:
                self._send_unban_event(member)
            time.sleep(0)

    def _unban_memory_inside(self, coverage: NetworkCoverage) -> list[str]:
        removed: list[str] = []
        kept: list[tuple[_Network, float]] = []
        for banned, expiry in self.banned_networks:
            if coverage.covers_network(banned):
                removed.append(str(banned))
            else:
                kept.append((banned, expiry))
        self.banned_networks = kept
        keys = list(Cache.__iter__(self.banned_ips))
        for start in range(0, len(keys), _MEMORY_BATCH):
            for ip in keys[start : start + _MEMORY_BATCH]:
                if coverage.covers_address(ip):
                    self._purge_banned_ip(ip)
                    removed.append(ip)
            time.sleep(0)
        return removed

    def _unban_redis_inside(self, coverage: NetworkCoverage) -> list[str]:
        removed: list[str] = []
        prefix = self.redis_handler.config.redis_prefix
        try:
            with self.redis_handler.get_connection() as conn:
                for namespace in ("banned_ips", "banned_networks"):
                    stem = f"{prefix}{namespace}:"
                    batch: list[str] = []
                    for key in conn.scan_iter(match=f"{stem}*", count=_BATCH):
                        member = key[len(stem) :]
                        if _member_covered(namespace, member, coverage):
                            batch.append(key)
                            removed.append(member)
                        if len(batch) >= _BATCH:
                            conn.unlink(*batch)
                            batch.clear()
                            time.sleep(0)
                    if batch:
                        conn.unlink(*batch)
        except Exception as e:
            self.logger.warning("Redis unban of whitelisted ranges failed: %s", e)
        return removed

    def unban_ip(self, ip: str) -> None:
        if "/" in ip:
            self._unban_cidr(ip)
            return
        ip = _canonicalize_ip(ip)
        self._purge_banned_ip(ip)

        if self.redis_handler:
            self.redis_handler.delete("banned_ips", ip)

        self._forget_strikes(ip)

        if self.agent_handler:
            self._send_unban_event(ip)

    def reset(self) -> None:
        self.banned_ips.clear()
        self.banned_networks.clear()
        if self.redis_handler:
            self._unlink_prefixed(("banned_ips:*",))
        self._forget_all_strikes()
