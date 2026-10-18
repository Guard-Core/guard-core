import ipaddress
import logging
import time
from collections.abc import Callable, Iterable, MutableMapping
from typing import Any

from guard_core.sync.handlers._ipban_cache import _Network
from guard_core.sync.handlers._ipban_coverage import NetworkCoverage
from guard_core.sync.handlers._ipban_events import IpBanEventMixin
from guard_core.sync.handlers._ipban_lookup import IpBanLookupMixin
from guard_core.sync.handlers._ipban_rule_exempt import IpBanRuleExemptionMixin
from guard_core.sync.handlers.redis_handler import scan_unlink
from guard_core.sync.utils import _canonicalize_ip

_BATCH = 2000
_MEMORY_BATCH = 1000
_EVENT_BATCH = 100
_STRIKE_PATTERNS = ("rate_limit:violations:*", "detection:strikes*")


def _network_member_covered(member: str, coverage: NetworkCoverage) -> bool:
    try:
        return coverage.covers_network(ipaddress.ip_network(member, strict=False))
    except ValueError:
        return False


def _member_covered(namespace: str, member: str, coverage: NetworkCoverage) -> bool:
    if namespace == "banned_ips":
        return coverage.covers_address(member)
    return _network_member_covered(member, coverage)


def _strike_key_inside(coverage: NetworkCoverage, stem: str) -> Callable[[str], bool]:
    def inside(key: str) -> bool:
        return _network_member_covered(key[len(stem) :].split("|", 1)[0], coverage)

    return inside


class IpBanQueryMixin(IpBanLookupMixin, IpBanEventMixin, IpBanRuleExemptionMixin):
    banned_ips: MutableMapping[str, float]
    banned_networks: list[tuple[_Network, float]]
    redis_handler: Any = None
    logger: logging.Logger

    def _unban_cidr(self, cidr: str, reason: str) -> None:
        network = ipaddress.ip_network(cidr, strict=False)
        self.banned_networks = [
            (banned, expiry)
            for banned, expiry in self.banned_networks
            if banned != network
        ]
        self._purge_banned_ip(str(network))
        if self.redis_handler:
            self.redis_handler.delete("banned_networks", str(network))
            self.redis_handler.delete("banned_identities", str(network))
        self._forget_strikes(str(network))
        self._bump_ban_version()
        if self.agent_handler:
            self._send_unban_event(str(network), reason)

    def _unban_identity(self, identity: str) -> None:
        self._purge_banned_ip(identity)
        if self.redis_handler:
            self.redis_handler.delete("banned_identities", identity)
        self._forget_strikes(identity)

    def unban_inside(self, entries: Iterable[str]) -> None:
        networks = [ipaddress.ip_network(entry, strict=False) for entry in entries]
        if not networks:
            return
        coverage = NetworkCoverage(networks)
        removed = self._unban_memory_inside(coverage)
        if self.redis_handler:
            removed.extend(self._unban_redis_inside(coverage))
        members = list(dict.fromkeys(removed))
        self._bump_ban_version()
        self._forget_strikes_of(members)
        if self.agent_handler:
            self._send_unban_events(members, "dynamic_rule_whitelist")

    def _forget_strikes_of(self, members: list[str]) -> None:
        for start in range(0, len(members), _EVENT_BATCH):
            for member in members[start : start + _EVENT_BATCH]:
                self._forget_strikes(member)
            time.sleep(0)

    def _forget_strikes(self, ip: str, strict: bool = False) -> None:
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
            if strict:
                raise
            self.logger.warning("Redis strikes of %s could not be cleared: %s", ip, e)

    def forget_strikes_of_ip(self, ip: str, strict: bool = False) -> None:
        self._forget_strikes(_canonicalize_ip(ip), strict)

    def forget_strikes_inside(
        self, entries: Iterable[str], strict: bool = False
    ) -> None:
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
            if strict:
                raise
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

    def _send_unban_events(self, members: list[str], reason: str) -> None:
        for start in range(0, len(members), _EVENT_BATCH):
            for member in members[start : start + _EVENT_BATCH]:
                self._send_unban_event(member, reason)
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
        keys = list(self.banned_ips)
        for start in range(0, len(keys), _MEMORY_BATCH):
            for ip in keys[start : start + _MEMORY_BATCH]:
                if _member_covered(
                    "banned_identities" if "/" in ip else "banned_ips", ip, coverage
                ):
                    self._purge_banned_ip(ip)
                    removed.append(ip)
            time.sleep(0)
        return removed

    def _unban_redis_inside(self, coverage: NetworkCoverage) -> list[str]:
        removed: list[str] = []
        prefix = self.redis_handler.config.redis_prefix
        try:
            with self.redis_handler.get_connection() as conn:
                for namespace in ("banned_ips", "banned_networks", "banned_identities"):
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

    def unban_ip(self, ip: str, *, reason: str = "manual_unban") -> None:
        if "/" in ip:
            self._unban_cidr(ip, reason)
            return
        ip = _canonicalize_ip(ip)
        identity = self._grouped_identity_of(ip)
        self._purge_banned_ip(ip)

        if self.redis_handler:
            self.redis_handler.delete("banned_ips", ip)

        self._forget_strikes(ip)
        if identity is not None:
            self._unban_identity(identity)
        self._bump_ban_version()

        if self.agent_handler:
            self._send_unban_event(ip, reason)

    def reset(self) -> None:
        self.banned_ips.clear()
        self.banned_networks.clear()
        if self.redis_handler:
            self._unlink_prefixed(
                ("banned_ips:*", "banned_networks:*", "banned_identities:*")
            )
        self._bump_ban_version()
        self._forget_shared_state()
        self._forget_all_strikes()
