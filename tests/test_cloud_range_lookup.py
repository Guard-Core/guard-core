import ipaddress
import random
from collections.abc import Iterable
from unittest.mock import patch

import pytest

from guard_core.handlers.cloud_handler import CloudManager, cloud_handler

Network = ipaddress.IPv4Network | ipaddress.IPv6Network


def _reference_is_cloud_ip(
    ip: str,
    ranges: set[Network],
    regions: dict[str, str],
    carve_outs: set[str],
) -> bool:
    address = ipaddress.ip_address(ip)
    for network in ranges:
        if address in network:
            if carve_outs and regions.get(str(network)) in carve_outs:
                continue
            return True
    return False


def _random_networks(rng: random.Random, count: int) -> set[Network]:
    networks: set[Network] = set()
    while len(networks) < count:
        if rng.random() < 0.6:
            length = rng.choice([8, 12, 16, 20, 24, 28, 32])
            address = ipaddress.IPv4Address(rng.getrandbits(32))
            networks.add(ipaddress.ip_network(f"{address}/{length}", strict=False))
        else:
            length = rng.choice([32, 48, 56, 64, 96, 128])
            address6 = ipaddress.IPv6Address(rng.getrandbits(128))
            networks.add(ipaddress.ip_network(f"{address6}/{length}", strict=False))
    return networks


def _random_addresses(
    rng: random.Random, networks: Iterable[Network], count: int
) -> list[str]:
    picked = list(networks)
    addresses = []
    for _ in range(count):
        if rng.random() < 0.7:
            network = rng.choice(picked)
            offset = rng.randrange(network.num_addresses)
            addresses.append(str(network[offset]))
        elif rng.random() < 0.5:
            addresses.append(str(ipaddress.IPv4Address(rng.getrandbits(32))))
        else:
            addresses.append(str(ipaddress.IPv6Address(rng.getrandbits(128))))
    return addresses


@pytest.mark.parametrize("seed", range(5))
def test_the_verdict_equals_the_linear_scan_for_nested_and_carved_out_ranges(
    seed: int,
) -> None:
    rng = random.Random(seed)
    manager = cloud_handler
    ranges = _random_networks(rng, 400)
    nested = {
        ipaddress.ip_network(f"{network.network_address}/{network.prefixlen + 2}")
        for network in list(ranges)[:80]
        if network.prefixlen + 2 <= network.max_prefixlen
    }
    ranges |= nested
    regions = {
        str(network): rng.choice(["us-east-1", "eu-west-1", "ap-south-1"])
        for network in ranges
    }
    manager.ip_ranges["AWS"] = ranges
    manager.network_regions["AWS"] = regions

    for address in _random_addresses(rng, ranges, 1500):
        assert manager.is_cloud_ip(address, {"AWS"}) == _reference_is_cloud_ip(
            address, ranges, regions, set()
        )
        assert manager.is_cloud_ip(
            address, {"AWS:!us-east-1"}
        ) == _reference_is_cloud_ip(address, ranges, regions, {"us-east-1"})
        assert manager.is_cloud_ip(
            address, {"AWS:!us-east-1", "AWS:!eu-west-1"}
        ) == _reference_is_cloud_ip(
            address, ranges, regions, {"us-east-1", "eu-west-1"}
        )


def test_a_lookup_does_not_test_every_network_of_the_provider() -> None:
    manager = CloudManager()
    networks = {
        ipaddress.ip_network(f"{(n >> 8) % 224 + 1}.{n % 256}.0.0/16")
        for n in range(50_000)
    }
    manager.ip_ranges["AWS"] = networks
    contains_calls = 0
    original = ipaddress.IPv4Network.__contains__

    def counting_contains(self: ipaddress.IPv4Network, other: object) -> bool:
        nonlocal contains_calls
        contains_calls += 1
        return bool(original(self, other))

    with patch.object(ipaddress.IPv4Network, "__contains__", counting_contains):
        manager.is_cloud_ip("8.8.8.8", {"AWS"})

    assert contains_calls <= 64


def test_replacing_the_ranges_is_seen_by_the_next_lookup() -> None:
    manager = CloudManager()
    manager.ip_ranges["AWS"] = {ipaddress.ip_network("198.51.100.0/24")}
    assert manager.is_cloud_ip("198.51.100.7", {"AWS"}) is True

    manager.ip_ranges["AWS"] = {ipaddress.ip_network("203.0.113.0/24")}

    assert manager.is_cloud_ip("198.51.100.7", {"AWS"}) is False
    assert manager.is_cloud_ip("203.0.113.7", {"AWS"}) is True
