import ipaddress
from collections.abc import Iterable

from guard_core.handlers._ipban_cache import _Network


class IpBanRuleExemptionMixin:
    rule_exempt_networks: tuple[_Network, ...] = ()

    def set_rule_exempt_ips(self, entries: Iterable[str]) -> None:
        self.rule_exempt_networks = tuple(
            ipaddress.ip_network(entry, strict=False) for entry in entries
        )

    def _is_rule_exempt_target(self, target: _Network) -> bool:
        return any(
            target.version == network.version
            and target.network_address in network
            and target.broadcast_address in network
            for network in self.rule_exempt_networks
        )

    def _is_rule_exempt_ip(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(
            addr.version == network.version and addr in network
            for network in self.rule_exempt_networks
        )
