import ipaddress
import logging
import time
from collections.abc import MutableMapping
from typing import Any

from guard_core._utils.ip_extraction import MALFORMED_FORWARDED_FOR_PREFIX
from guard_core._utils.whitelist_match import parsed_networks
from guard_core.handlers._ipban_cache import _BanStore, _Network
from guard_core.handlers._ipban_events import IpBanEventMixin
from guard_core.handlers._ipban_recidive import IpBanRecidiveMixin
from guard_core.handlers._ipban_rule_exempt import (
    DYNAMIC_RULE_BAN_REASON,
    IpBanRuleExemptionMixin,
)
from guard_core.handlers._ipban_version import _VERSION_PAIR, IpBanVersionMixin
from guard_core.utils import _canonicalize_ip

_MAX_TRACKED_REFUSED_BANS = 10_000

_LOOPBACK_NETWORKS: tuple[_Network, ...] = (
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
)


class IpBanOperationsMixin(
    IpBanVersionMixin, IpBanEventMixin, IpBanRuleExemptionMixin, IpBanRecidiveMixin
):
    banned_ips: MutableMapping[str, float]
    banned_networks: list[tuple[_Network, float]]
    refused_ban_reported_until: dict[str, float]
    evictions_count: int
    evicted_to_report: list[tuple[str, float, int]]
    MAX_LOCAL_BANS: int
    config: Any = None
    redis_handler: Any = None
    logger: logging.Logger

    def _assert_positive_duration(self, duration: int) -> None:
        if duration <= 0:
            raise ValueError(f"ban duration must be positive, got {duration}")

    def _warn_kept_in_this_process(self, ip: str, cause: str) -> None:
        self.logger.warning(
            "Redis unavailable (%s): the ban of %s is kept in this process only",
            cause,
            ip,
        )

    async def _ban_cidr(self, ip: str, duration: int, reason: str) -> None:
        try:
            network = ipaddress.ip_network(ip, strict=False)
        except ValueError as e:
            raise ValueError(f"Invalid CIDR network {ip!r}: {e}") from e

        if self.redis_handler is None:
            self._remember_network_ban(network, time.time() + duration)
        else:
            await self._store_cidr_ban_in_redis(network, duration, reason)

        if self.agent_handler:
            await self._send_ban_event(str(network), duration, reason)

    def _remember_network_ban(self, network: _Network, expiry: float) -> None:
        held = [until for banned, until in self.banned_networks if banned == network]
        self.banned_networks = [
            entry for entry in self.banned_networks if entry[0] != network
        ]
        self.banned_networks.append((network, max([expiry, *held])))

    async def _store_cidr_ban_in_redis(
        self, network: _Network, duration: int, reason: str = "operator"
    ) -> None:
        expiry = time.time() + duration
        try:
            await self.redis_handler.write_ban_extending_only(
                "banned_networks",
                str(network),
                str(expiry),
                duration,
                version=_VERSION_PAIR,
                advance_version=True,
                rule_owned=reason == DYNAMIC_RULE_BAN_REASON,
            )
        except Exception:
            self._warn_kept_in_this_process(str(network), "request failed")
            self._remember_network_ban(network, expiry)

    async def _ban_exact_ip(self, ip: str, duration: int, reason: str) -> None:
        self._assert_valid_exact_ip(ip)
        await self._store_ban("banned_ips", ip, duration, reason)

    def _assert_valid_exact_ip(self, ip: str) -> None:
        if ip.startswith(MALFORMED_FORWARDED_FOR_PREFIX):
            return
        try:
            ipaddress.ip_address(ip)
        except ValueError as e:
            raise ValueError(f"Invalid IP address {ip!r}: {e}") from e

    def _identity_ban_key(self, identity: str) -> str:
        try:
            return str(ipaddress.ip_network(identity, strict=False))
        except ValueError as e:
            raise ValueError(f"Invalid identity {identity!r}: {e}") from e

    async def _ban_identity(self, identity: str, duration: int, reason: str) -> None:
        await self._store_ban(
            "banned_identities", self._identity_ban_key(identity), duration, reason
        )

    async def _store_ban(
        self,
        namespace: str,
        key: str,
        duration: int,
        reason: str,
        recidive_count: int | None = None,
    ) -> None:
        expiry = time.time() + duration
        backed = bool(self.redis_handler)
        self._remember_ban(key, expiry, backed)

        if backed:
            try:
                kept = await self.redis_handler.write_ban_extending_only(
                    namespace,
                    key,
                    str(expiry),
                    duration,
                    version=_VERSION_PAIR,
                    rule_owned=reason == DYNAMIC_RULE_BAN_REASON,
                )
                self._remember_ban(key, kept, True)
            except Exception:
                self._warn_kept_in_this_process(key, "request failed")
                self._remember_ban(key, expiry, False)

        if recidive_count is not None:
            self.logger.info(
                "Banned %s for %d seconds (ban %d within the recidive window)",
                key,
                duration,
                recidive_count,
            )
        if self.agent_handler:
            await self._report_evictions()
            await self._send_ban_event(key, duration, reason, recidive_count)

    def _ban_target(self, ip: str, grouped: bool) -> tuple[str, str]:
        if grouped:
            return "banned_identities", self._identity_ban_key(ip)
        self._assert_valid_exact_ip(ip)
        return "banned_ips", ip

    def _remember_ban(self, key: str, expiry: float, backed_by_redis: bool) -> None:
        local = self._local_expiry(expiry) if backed_by_redis else expiry
        self.banned_ips[key] = max(local, self.banned_ips.get(key, 0.0))
        if not backed_by_redis and isinstance(self.banned_ips, _BanStore):
            self.banned_ips.mark_memory_only(key)

    async def disown_rule_ban(self, ip: str) -> None:
        """Take the ban of ip, an address or a CIDR, out of the set of bans a
        dynamic rule owns."""
        if not self.redis_handler:
            return
        ip = _canonicalize_ip(ip)
        if "/" in ip:
            namespace = "banned_networks"
            key = str(ipaddress.ip_network(ip, strict=False))
        else:
            namespace, key = "banned_ips", ip
        await self.redis_handler.disown_ban(namespace, key)

    async def purge_rule_owned_bans(self) -> dict[str, int]:
        """Lift every ban a dynamic rule owns: down to the foreign ban it hid
        (its floor) or off, leaving a ban that something longer replaced. One
        script call per owned ban, then the local copies go and the ban version
        advances once, so every worker reloads."""
        counts = {"gone": 0, "deleted": 0, "rewritten": 0, "kept": 0, "failed": 0}
        if not self.redis_handler:
            return counts
        prefix = self.redis_handler.config.redis_prefix
        outcomes = ("gone", "deleted", "rewritten", "kept")
        for member in await self.redis_handler.owned_ban_members():
            try:
                counts[outcomes[await self.redis_handler.purge_owned_ban(member)]] += 1
            except Exception as error:
                counts["failed"] += 1
                self.logger.error("Purging the rule ban %s failed: %s", member, error)
                continue
            self._drop_local_ban(member[len(prefix) :])
        await self._bump_ban_version()
        return counts

    def _drop_local_ban(self, namespaced_key: str) -> None:
        namespace, _, key = namespaced_key.partition(":")
        if namespace == "banned_networks":
            self.banned_networks = [
                entry for entry in self.banned_networks if str(entry[0]) != key
            ]
        self.banned_ips.pop(key, None)

    def _target_network(self, ip: str) -> _Network | None:
        try:
            if "/" in ip:
                return ipaddress.ip_network(ip, strict=False)
            return ipaddress.ip_network(ipaddress.ip_address(ip))
        except ValueError:
            return None

    def _trusted_proxy_networks(self) -> list[_Network]:
        trusted_proxies = getattr(self.config, "trusted_proxies", None) or ()
        return list(parsed_networks(tuple(trusted_proxies)))

    def _self_dos_refusal_reason(self, ip: str) -> str | None:
        target = self._target_network(ip)
        if target is None:
            return None
        if any(
            target.version == network.version and target.overlaps(network)
            for network in _LOOPBACK_NETWORKS
        ):
            return "loopback"
        if any(
            target.version == network.version and target.overlaps(network)
            for network in self._trusted_proxy_networks()
        ):
            return "trusted_proxy"
        return None

    def _log_refused_ban(self, ip: str, reason: str) -> None:
        space = "loopback" if reason == "loopback" else "a configured trusted proxy"
        self.logger.warning(
            "Refused to ban %s: overlaps %s space and would self-DoS this "
            "deployment. If unexpected, trusted_proxies is likely unset "
            "behind a reverse proxy; see docs/configuration/security-config.md",
            ip,
            space,
        )

    def _refusal_already_reported(self, ip: str, duration: int) -> bool:
        now = time.time()
        reported = self.refused_ban_reported_until
        if reported.get(ip, 0.0) > now:
            return True
        if len(reported) >= _MAX_TRACKED_REFUSED_BANS:
            for stale in [key for key, until in reported.items() if until <= now]:
                del reported[stale]
        if len(reported) >= _MAX_TRACKED_REFUSED_BANS:
            del reported[next(iter(reported))]
        reported.pop(ip, None)
        reported[ip] = now + duration
        return False

    async def _report_refused_ban(
        self, ip: str, refusal: str, duration: int, reason: str
    ) -> None:
        if self._refusal_already_reported(ip, duration):
            return
        self._log_refused_ban(ip, refusal)
        if self.agent_handler:
            await self._send_ban_refused_event(ip, duration, reason, refusal)

    def _refuse_rule_exempt_target(self, ip: str) -> bool:
        target = self._target_network(ip)
        if target is None or not self._is_rule_exempt_target(target):
            return False
        self.logger.info(
            "Refused to ban %s: covered by an active dynamic rule ip_whitelist entry",
            ip,
        )
        return True

    def _warn_if_private_target(self, ip: str) -> None:
        target = self._target_network(ip)
        if target is None:
            return
        if not target.is_private:
            return
        self.logger.warning(
            "Banning private IP range %s: if requests reach this service through "
            "a reverse proxy, this IP may be the proxy and the ban will block ALL "
            "users. Verify config.trusted_proxies lists the proxy IP(s); see "
            "docs/configuration/security-config.md",
            ip,
        )

    async def ban_ip(
        self,
        ip: str,
        duration: int,
        reason: str = "threshold_exceeded",
        *,
        grouped: bool = False,
    ) -> bool:
        applied = await self._apply_ban(ip, duration, reason, grouped, escalate=False)
        return applied is not None

    async def _ban_ip_escalating(
        self,
        ip: str,
        duration: int,
        reason: str = "threshold_exceeded",
        *,
        grouped: bool = False,
    ) -> int | None:
        """The automatic ban engine's entry: a repeat ban lasts longer when
        ``enable_recidive`` is on. Returns the duration applied (None when the ban
        was refused). Public ``ban_ip`` is the same body without escalation, so
        manual and dynamic-rule bans neither escalate nor count."""
        return await self._apply_ban(ip, duration, reason, grouped, escalate=True)

    async def _apply_ban(
        self, ip: str, duration: int, reason: str, grouped: bool, escalate: bool
    ) -> int | None:
        ip = _canonicalize_ip(ip)
        self._assert_positive_duration(duration)
        if self._refuse_rule_exempt_target(ip):
            return None
        refusal = self._self_dos_refusal_reason(ip)
        if refusal is not None:
            await self._report_refused_ban(ip, refusal, duration, reason)
            return None
        self._warn_if_private_target(ip)
        if escalate and self._recidive_applies(ip, grouped):
            namespace, key = self._ban_target(ip, grouped)
            applied, count = await self._escalated_ban_terms(namespace, key, duration)
            await self._store_ban(namespace, key, applied, reason, count)
            return applied
        if grouped:
            await self._ban_identity(ip, duration, reason)
        elif "/" in ip:
            await self._ban_cidr(ip, duration, reason)
        else:
            await self._ban_exact_ip(ip, duration, reason)
        return duration
