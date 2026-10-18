import ipaddress
import logging
import time
from typing import Any

from cachetools import TTLCache

from guard_core.handlers._ipban_cache import _Network
from guard_core.handlers._ipban_events import IpBanEventMixin
from guard_core.handlers._ipban_rule_exempt import IpBanRuleExemptionMixin
from guard_core.utils import _canonicalize_ip

_MAX_TRACKED_REFUSED_BANS = 10_000

_LOOPBACK_NETWORKS: tuple[_Network, ...] = (
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
)


class IpBanOperationsMixin(IpBanEventMixin, IpBanRuleExemptionMixin):
    LOCAL_CACHE_TTL_CAP_SECONDS: int
    banned_ips: TTLCache
    banned_networks: list[tuple[_Network, float]]
    refused_ban_reported_until: dict[str, float]
    config: Any = None
    redis_handler: Any = None
    logger: logging.Logger

    def _assert_positive_duration(self, duration: int) -> None:
        if duration <= 0:
            raise ValueError(f"ban duration must be positive, got {duration}")

    def _clamp_to_local_cap(self, duration: int, cause: str) -> int:
        if duration <= self.LOCAL_CACHE_TTL_CAP_SECONDS:
            return duration
        self.logger.warning(
            "Redis unavailable (%s): ban shortened from %ds to %ds so "
            "protection still applies",
            cause,
            duration,
            self.LOCAL_CACHE_TTL_CAP_SECONDS,
        )
        return self.LOCAL_CACHE_TTL_CAP_SECONDS

    async def _ban_cidr(self, ip: str, duration: int) -> None:
        try:
            network = ipaddress.ip_network(ip, strict=False)
        except ValueError as e:
            raise ValueError(f"Invalid CIDR network {ip!r}: {e}") from e

        if self.redis_handler is None:
            duration = self._clamp_to_local_cap(duration, "not configured")
            self.banned_networks.append((network, time.time() + duration))
            return

        try:
            await self.redis_handler.set_key(
                "banned_networks",
                str(network),
                str(time.time() + duration),
                ttl=duration,
            )
        except Exception:
            duration = self._clamp_to_local_cap(duration, "request failed")
            self.banned_networks.append((network, time.time() + duration))

    async def _ban_exact_ip(self, ip: str, duration: int, reason: str) -> None:
        try:
            ipaddress.ip_address(ip)
        except ValueError as e:
            raise ValueError(f"Invalid IP address {ip!r}: {e}") from e

        if self.redis_handler is None:
            duration = self._clamp_to_local_cap(duration, "not configured")

        expiry = time.time() + duration
        self.banned_ips[ip] = expiry

        if self.redis_handler:
            try:
                await self.redis_handler.set_key(
                    "banned_ips", ip, str(expiry), ttl=duration
                )
            except Exception:
                duration = self._clamp_to_local_cap(duration, "request failed")
                self.banned_ips[ip] = time.time() + duration

        if self.agent_handler:
            await self._send_ban_event(ip, duration, reason)

    def _target_network(self, ip: str) -> _Network | None:
        try:
            if "/" in ip:
                return ipaddress.ip_network(ip, strict=False)
            return ipaddress.ip_network(ipaddress.ip_address(ip))
        except ValueError:
            return None

    def _trusted_proxy_networks(self) -> list[_Network]:
        trusted_proxies = getattr(self.config, "trusted_proxies", None) or ()
        networks = []
        for entry in trusted_proxies:
            try:
                networks.append(ipaddress.ip_network(entry, strict=False))
            except ValueError:
                continue
        return networks

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
        self, ip: str, duration: int, reason: str = "threshold_exceeded"
    ) -> bool:
        ip = _canonicalize_ip(ip)
        self._assert_positive_duration(duration)
        if self._refuse_rule_exempt_target(ip):
            return False
        refusal = self._self_dos_refusal_reason(ip)
        if refusal is not None:
            await self._report_refused_ban(ip, refusal, duration, reason)
            return False
        self._warn_if_private_target(ip)
        if "/" in ip:
            await self._ban_cidr(ip, duration)
        else:
            await self._ban_exact_ip(ip, duration, reason)
        return True
