import logging
import threading
from collections import OrderedDict
from collections.abc import Iterable
from ipaddress import IPv4Address, IPv6Address, IPv6Network

from guard_core.sync._utils.sampling import observe_sampled_key

logger = logging.getLogger("guard_core")

_NAT64_WELL_KNOWN_PREFIX = IPv6Network("64:ff9b::/96")
_NAT64_IPV4_OCTET_BIT_POSITIONS = {
    32: (32, 40, 48, 56),
    40: (40, 48, 56, 72),
    48: (48, 56, 72, 80),
    56: (56, 72, 80, 88),
    64: (72, 80, 88, 96),
    96: (96, 104, 112, 120),
}
NAT64_PREFIX_LENGTHS = frozenset(_NAT64_IPV4_OCTET_BIT_POSITIONS)
_nat64_prefixes: tuple[IPv6Network, ...] = ()
_non_global_warnings: OrderedDict[str, float] = OrderedDict()
_non_global_warning_lock = threading.Lock()
_NON_GLOBAL_WARNING_WINDOW_SECONDS = 60


def configure_nat64_prefixes(prefixes: Iterable[IPv6Network]) -> None:
    global _nat64_prefixes
    _nat64_prefixes = tuple(prefixes)


def _decode_nat64_embedded_ipv4(addr: IPv6Address, prefix: IPv6Network) -> IPv4Address:
    value = int(addr)
    positions = _NAT64_IPV4_OCTET_BIT_POSITIONS[prefix.prefixlen]
    return IPv4Address(bytes((value >> (120 - bit)) & 0xFF for bit in positions))


def _nat64_prefix_of(addr: IPv6Address) -> IPv6Network | None:
    if addr in _NAT64_WELL_KNOWN_PREFIX:
        return _NAT64_WELL_KNOWN_PREFIX
    return next((prefix for prefix in _nat64_prefixes if addr in prefix), None)


def _unwrap_nat64(addr: IPv6Address) -> IPv4Address | None:
    prefix = _nat64_prefix_of(addr)
    if prefix is None:
        return None
    embedded = _decode_nat64_embedded_ipv4(addr, prefix)
    if embedded.is_global:
        return embedded
    if observe_sampled_key(
        _non_global_warnings,
        _non_global_warning_lock,
        "nat64-non-global",
        window=_NON_GLOBAL_WARNING_WINDOW_SECONDS,
        max_tracked=1,
    ):
        logger.warning(
            "A NAT64 address embeds the non-global IPv4 address %s, so it stays "
            "an IPv6 identity instead of posing as that IPv4 address. Logged "
            "once a minute.",
            embedded,
        )
    return None
