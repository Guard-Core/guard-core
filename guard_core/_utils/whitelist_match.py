from collections.abc import Sequence
from functools import lru_cache
from ipaddress import IPv4Address, IPv6Address, ip_network

Address = IPv4Address | IPv6Address
_Buckets = tuple[tuple[int, dict[int, str]], ...]


@lru_cache(maxsize=8)
def _entry_index(entries: tuple[str, ...]) -> dict[int, _Buckets]:
    """One bucket per prefix length, longest first, built per distinct whitelist.

    NetworkCoverage merges overlapping and adjacent entries into spans, which
    loses which entry matched; this index keeps every entry as written so the
    most specific one can be named.
    """
    by_length: dict[tuple[int, int], dict[int, str]] = {}
    for entry in entries:
        network = ip_network(entry, strict=False)
        key = (network.version, network.prefixlen)
        by_length.setdefault(key, {})[int(network.network_address)] = str(network)
    index: dict[int, _Buckets] = {}
    for version in (4, 6):
        buckets = sorted(
            (
                (prefixlen, members)
                for (entry_version, prefixlen), members in by_length.items()
                if entry_version == version
            ),
            key=lambda bucket: bucket[0],
            reverse=True,
        )
        index[version] = tuple(buckets)
    return index


def most_specific_whitelist_entry(
    address: Address, entries: Sequence[str]
) -> str | None:
    value = int(address)
    bits = address.max_prefixlen
    for prefixlen, members in _entry_index(tuple(entries))[address.version]:
        shift = bits - prefixlen
        entry = members.get(value >> shift << shift)
        if entry is not None:
            return entry
    return None
