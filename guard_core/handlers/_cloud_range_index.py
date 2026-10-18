import ipaddress
from collections.abc import Iterator

Network = ipaddress.IPv4Network | ipaddress.IPv6Network
Address = ipaddress.IPv4Address | ipaddress.IPv6Address


class NetworkIndex:
    """Finds every network containing an address with one dict lookup per prefix length.

    Cloud ranges nest and overlap, and a carve-out can skip the first match, so the
    lookup yields all containing networks, longest prefix first.
    """

    def __init__(self, networks: set[Network]) -> None:
        self._source = networks
        self._size = len(networks)
        self._buckets: dict[int, list[tuple[int, dict[int, Network]]]] = {4: [], 6: []}
        by_length: dict[tuple[int, int], dict[int, Network]] = {}
        for network in networks:
            key = (network.version, network.prefixlen)
            by_length.setdefault(key, {})[int(network.network_address)] = network
        for (version, prefixlen), members in by_length.items():
            self._buckets[version].append((prefixlen, members))
        for version in self._buckets:
            self._buckets[version].sort(key=lambda bucket: bucket[0], reverse=True)

    def describes(self, networks: set[Network]) -> bool:
        return networks is self._source and len(networks) == self._size

    def containing(self, address: Address) -> Iterator[Network]:
        value = int(address)
        bits = address.max_prefixlen
        for prefixlen, members in self._buckets[address.version]:
            network = members.get(value >> (bits - prefixlen) << (bits - prefixlen))
            if network is not None:
                yield network
