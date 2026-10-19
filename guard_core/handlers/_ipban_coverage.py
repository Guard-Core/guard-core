import ipaddress
from bisect import bisect_right
from collections.abc import Iterable

from guard_core.handlers._ipban_cache import _Network


class NetworkCoverage:
    def __init__(self, networks: Iterable[_Network]) -> None:
        spans: dict[int, list[tuple[int, int]]] = {4: [], 6: []}
        for network in networks:
            spans[network.version].append(
                (int(network.network_address), int(network.broadcast_address))
            )
        self._starts: dict[int, list[int]] = {}
        self._ends: dict[int, list[int]] = {}
        for version, version_spans in spans.items():
            merged: list[list[int]] = []
            for start, end in sorted(version_spans):
                if merged and start <= merged[-1][1] + 1:
                    merged[-1][1] = max(merged[-1][1], end)
                else:
                    merged.append([start, end])
            self._starts[version] = [span[0] for span in merged]
            self._ends[version] = [span[1] for span in merged]

    def _covers(self, version: int, start: int, end: int) -> bool:
        index = bisect_right(self._starts[version], start) - 1
        return index >= 0 and end <= self._ends[version][index]

    def covers_address(self, text: str) -> bool:
        try:
            address = ipaddress.ip_address(text)
        except ValueError:
            return False
        value = int(address)
        return self._covers(address.version, value, value)

    def covers_member(self, text: str) -> bool:
        try:
            network = ipaddress.ip_network(text, strict=False)
        except ValueError:
            return False
        return self.covers_network(network)

    def covers_network(self, network: _Network) -> bool:
        return self._covers(
            network.version,
            int(network.network_address),
            int(network.broadcast_address),
        )
