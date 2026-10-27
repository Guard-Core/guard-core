import logging
from collections.abc import Iterable
from ipaddress import IPv4Address, IPv6Address, IPv6Network

from guard_core.sync._utils.app_managers import _HELD_ATTRIBUTE, hold_for_app
from guard_core.sync._utils.sampling import SampledKeys, observe_sampled_key

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
_NON_GLOBAL_WARNING_WINDOW_SECONDS = 60
_HELD_KIND = "nat64"


class Nat64Table:
    """The network-specific NAT64 prefixes of one app and its once-a-minute warning.

    An app's table is never edited: a new configuration holds a new table, so the
    caches keyed on a table cannot serve a decoding of the old prefixes.
    """

    def __init__(self, prefixes: Iterable[IPv6Network] = ()) -> None:
        self.prefixes = tuple(prefixes)
        self.warned = SampledKeys()


DEFAULT_NAT64_TABLE = Nat64Table()


def configure_nat64_prefixes(
    config: object, prefixes: Iterable[IPv6Network]
) -> Nat64Table:
    table = Nat64Table(prefixes)
    hold_for_app(config, _HELD_KIND, table)
    return table


def nat64_table_of(config: object) -> Nat64Table:
    try:
        table: Nat64Table = config.__dict__[_HELD_ATTRIBUTE][_HELD_KIND]
    except (AttributeError, KeyError):
        return DEFAULT_NAT64_TABLE
    return table


def _decode_nat64_embedded_ipv4(addr: IPv6Address, prefix: IPv6Network) -> IPv4Address:
    value = int(addr)
    positions = _NAT64_IPV4_OCTET_BIT_POSITIONS[prefix.prefixlen]
    return IPv4Address(bytes((value >> (120 - bit)) & 0xFF for bit in positions))


def _nat64_prefix_of(addr: IPv6Address, table: Nat64Table) -> IPv6Network | None:
    if addr in _NAT64_WELL_KNOWN_PREFIX:
        return _NAT64_WELL_KNOWN_PREFIX
    return next((prefix for prefix in table.prefixes if addr in prefix), None)


def _decoded_nat64_embedded_ipv4(
    addr: IPv6Address, table: Nat64Table = DEFAULT_NAT64_TABLE
) -> IPv4Address | None:
    prefix = _nat64_prefix_of(addr, table)
    if prefix is None:
        return None
    return _decode_nat64_embedded_ipv4(addr, prefix)


def _warn_non_global_embedded_once_a_minute(
    embedded: IPv4Address, table: Nat64Table = DEFAULT_NAT64_TABLE
) -> None:
    if observe_sampled_key(
        table.warned.entries,
        table.warned.lock,
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


def _unwrap_nat64(
    addr: IPv6Address, table: Nat64Table = DEFAULT_NAT64_TABLE
) -> IPv4Address | None:
    embedded = _decoded_nat64_embedded_ipv4(addr, table)
    if embedded is None:
        return None
    if embedded.is_global:
        return embedded
    _warn_non_global_embedded_once_a_minute(embedded, table)
    return None
