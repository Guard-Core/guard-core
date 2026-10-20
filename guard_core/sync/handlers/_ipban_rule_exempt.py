import ipaddress
from collections.abc import Iterable

from guard_core.sync.handlers._ipban_cache import _Network
from guard_core.sync.utils import _canonicalize_ip

DYNAMIC_RULE_BAN_REASON = "dynamic_rule"


def rule_ban_target(ip: str) -> tuple[str, str]:
    """The Redis namespace and key a rule ban on ip is stored under: the
    canonical address, or the normalized network for a CIDR."""
    try:
        if "/" in ip:
            return "banned_networks", str(ipaddress.ip_network(ip, strict=False))
    except ValueError:
        pass
    return "banned_ips", _canonicalize_ip(ip)


def rule_ban_member(ip: str) -> str:
    """The member a rule ban on ip has in the owned set, minus the Redis prefix."""
    namespace, key = rule_ban_target(ip)
    return f"{namespace}:{key}"


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
