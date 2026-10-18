import ipaddress
import logging
import time
from collections.abc import MutableMapping
from typing import Any

from guard_core.sync._utils.ip_extraction import MALFORMED_FORWARDED_FOR_PREFIX
from guard_core.sync.handlers._ipban_cache import _Network
from guard_core.sync.handlers._ipban_events import IpBanEventMixin
from guard_core.sync.handlers._ipban_rule_exempt import IpBanRuleExemptionMixin
from guard_core.sync.handlers._ipban_version import IpBanVersionMixin
from guard_core.sync.utils import _canonicalize_ip

_MAX_TRACKED_REFUSED_BANS = 10_000

_LOOPBACK_NETWORKS: tuple[_Network, ...] = (
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
)


class IpBanOperationsMixin(IpBanVersionMixin, IpBanEventMixin, IpBanRuleExemptionMixin):
    banned_ips: MutableMapping[str, float]
    banned_networks: list[tuple[_Network, float]]
    refused_ban_reported_until: dict[str, float]
    evictions_count: int
    evicted_to_report: tuple[str, float] | None
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

    def _ban_cidr(self, ip: str, duration: int, reason: str) -> None:
        try:
            network = ipaddress.ip_network(ip, strict=False)
        except ValueError as e:
            raise ValueError(f"Invalid CIDR network {ip!r}: {e}") from e

        if self.redis_handler is None:
            self.banned_networks.append((network, time.time() + duration))
        else:
            self._store_cidr_ban_in_redis(network, duration)

        if self.agent_handler:
            self._send_ban_event(str(network), duration, reason)

    def _store_cidr_ban_in_redis(self, network: _Network, duration: int) -> None:
        try:
            self.redis_handler.set_key(
                "banned_networks",
                str(network),
                str(time.time() + duration),
                ttl=duration,
            )
        except Exception:
            self._warn_kept_in_this_process(str(network), "request failed")
            self.banned_networks.append((network, time.time() + duration))
            return
        self._bump_ban_version()

    def _ban_exact_ip(self, ip: str, duration: int, reason: str) -> None:
        if not ip.startswith(MALFORMED_FORWARDED_FOR_PREFIX):
            try:
                ipaddress.ip_address(ip)
            except ValueError as e:
                raise ValueError(f"Invalid IP address {ip!r}: {e}") from e

        self._store_ban("banned_ips", ip, duration, reason)

    def _ban_identity(self, identity: str, duration: int, reason: str) -> None:
        try:
            network = ipaddress.ip_network(identity, strict=False)
        except ValueError as e:
            raise ValueError(f"Invalid identity {identity!r}: {e}") from e
        self._store_ban("banned_identities", str(network), duration, reason)

    def _store_ban(self, namespace: str, key: str, duration: int, reason: str) -> None:
        expiry = time.time() + duration
        self.banned_ips[key] = expiry

        if self.redis_handler:
            try:
                self.redis_handler.set_key(namespace, key, str(expiry), ttl=duration)
            except Exception:
                self._warn_kept_in_this_process(key, "request failed")

        if self.agent_handler:
            self._report_eviction()
            self._send_ban_event(key, duration, reason)

    def _report_eviction(self) -> None:
        evicted = self.evicted_to_report
        if evicted is None:
            return
        self.evicted_to_report = None
        self._send_ban_evicted_event(
            evicted[0],
            evicted[1],
            self.evictions_count,
            getattr(self.banned_ips, "maxsize", self.MAX_LOCAL_BANS),
        )

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

    def _report_refused_ban(
        self, ip: str, refusal: str, duration: int, reason: str
    ) -> None:
        if self._refusal_already_reported(ip, duration):
            return
        self._log_refused_ban(ip, refusal)
        if self.agent_handler:
            self._send_ban_refused_event(ip, duration, reason, refusal)

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

    def ban_ip(
        self,
        ip: str,
        duration: int,
        reason: str = "threshold_exceeded",
        *,
        grouped: bool = False,
    ) -> bool:
        ip = _canonicalize_ip(ip)
        self._assert_positive_duration(duration)
        if self._refuse_rule_exempt_target(ip):
            return False
        refusal = self._self_dos_refusal_reason(ip)
        if refusal is not None:
            self._report_refused_ban(ip, refusal, duration, reason)
            return False
        self._warn_if_private_target(ip)
        if grouped:
            self._ban_identity(ip, duration, reason)
        elif "/" in ip:
            self._ban_cidr(ip, duration, reason)
        else:
            self._ban_exact_ip(ip, duration, reason)
        return True
