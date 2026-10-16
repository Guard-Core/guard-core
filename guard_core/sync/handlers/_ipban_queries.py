import ipaddress
import time
from typing import Any

from cachetools import TTLCache

from guard_core.sync.handlers._ipban_cache import _Network
from guard_core.sync.handlers._ipban_events import IpBanEventMixin
from guard_core.sync.utils import _canonicalize_ip


class IpBanQueryMixin(IpBanEventMixin):
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

    def unban_ip(self, ip: str) -> None:
        if "/" in ip:
            self._unban_cidr(ip)
            return
        ip = _canonicalize_ip(ip)
        self._purge_banned_ip(ip)

        if self.redis_handler:
            self.redis_handler.delete("banned_ips", ip)

        if self.agent_handler:
            self._send_unban_event(ip)

    def reset(self) -> None:
        self.banned_ips.clear()
        self.banned_networks.clear()
        if self.redis_handler:
            with self.redis_handler.get_connection() as conn:
                keys = conn.keys(
                    f"{self.redis_handler.config.redis_prefix}banned_ips:*"
                )
                if keys:
                    conn.delete(*keys)
