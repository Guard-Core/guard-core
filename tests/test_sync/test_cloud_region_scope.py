import ipaddress
from collections.abc import Generator
from typing import Any

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.handlers.cloud_handler import (
    CloudManager,
    _decode_cached,
    _encode_cached,
    _parse_cloud_selectors,
)
from guard_core.sync.handlers.redis_handler import RedisManager


def test_security_config_keeps_region_selector() -> None:
    config = SyncSecurityConfig(block_cloud_providers={"GCP:!us-central1"})
    assert config.block_cloud_providers == {"GCP:!us-central1"}


def test_security_config_keeps_bare_provider() -> None:
    config = SyncSecurityConfig(block_cloud_providers={"GCP"})
    assert config.block_cloud_providers == {"GCP"}


def test_security_config_rejects_unknown_provider_selector() -> None:
    with pytest.raises(ValueError, match="Unknown cloud providers"):
        SyncSecurityConfig(block_cloud_providers={"Bogus:!x", "GCP"})


def test_parse_selectors_bare_provider() -> None:
    blocked, carveouts = _parse_cloud_selectors({"GCP"})
    assert blocked == {"GCP"}
    assert carveouts == {}


def test_parse_selectors_carveout() -> None:
    blocked, carveouts = _parse_cloud_selectors({"GCP:!us-central1"})
    assert blocked == {"GCP"}
    assert carveouts == {"GCP": {"us-central1"}}


def test_parse_selectors_mixed_providers_and_carveouts() -> None:
    blocked, carveouts = _parse_cloud_selectors(
        {"GCP", "GCP:!us-central1", "AWS:!us-east-1"}
    )
    assert blocked == {"GCP", "AWS"}
    assert carveouts == {"GCP": {"us-central1"}, "AWS": {"us-east-1"}}


def test_parse_selectors_carveout_implies_provider_block() -> None:
    blocked, carveouts = _parse_cloud_selectors({"AWS:!us-east-1"})
    assert blocked == {"AWS"}
    assert carveouts == {"AWS": {"us-east-1"}}


@pytest.fixture
def gcp_regions() -> Generator[tuple[CloudManager, str, str], None, None]:
    manager = CloudManager()
    saved_ranges = dict(manager.ip_ranges)
    saved_regions = dict(manager.network_regions)
    net_central = ipaddress.ip_network("34.100.0.0/24")
    net_europe = ipaddress.ip_network("35.200.0.0/24")
    manager.ip_ranges["GCP"] = {net_central, net_europe}
    manager.network_regions["GCP"] = {
        str(net_central): "us-central1",
        str(net_europe): "europe-west1",
    }
    yield manager, "34.100.0.5", "35.200.0.5"
    manager.ip_ranges = saved_ranges
    manager.network_regions = saved_regions


def test_block_whole_provider_unchanged(
    gcp_regions: tuple[CloudManager, str, str],
) -> None:
    manager, central_ip, europe_ip = gcp_regions
    assert manager.is_cloud_ip(central_ip, {"GCP"}) is True
    assert manager.is_cloud_ip(europe_ip, {"GCP"}) is True


def test_carveout_allows_excepted_region(
    gcp_regions: tuple[CloudManager, str, str],
) -> None:
    manager, central_ip, europe_ip = gcp_regions
    assert manager.is_cloud_ip(central_ip, {"GCP:!us-central1"}) is False
    assert manager.is_cloud_ip(europe_ip, {"GCP:!us-central1"}) is True


def test_carveout_other_region_still_blocked(
    gcp_regions: tuple[CloudManager, str, str],
) -> None:
    manager, central_ip, _ = gcp_regions
    assert manager.is_cloud_ip(central_ip, {"GCP:!europe-west1"}) is True


def test_non_cloud_ip_not_blocked(
    gcp_regions: tuple[CloudManager, str, str],
) -> None:
    manager, _, _ = gcp_regions
    assert manager.is_cloud_ip("8.8.8.8", {"GCP"}) is False
    assert manager.is_cloud_ip("8.8.8.8", {"GCP:!us-central1"}) is False


def test_cache_encode_decode_roundtrip_preserves_region() -> None:
    net_a = ipaddress.ip_network("34.100.0.0/24")
    net_b = ipaddress.ip_network("8.8.8.0/24")
    ranges = {net_a, net_b}
    regions = {str(net_a): "us-central1"}

    encoded = _encode_cached(ranges, regions)
    nets, decoded_regions = _decode_cached(encoded)

    assert nets == ranges
    assert decoded_regions == {str(net_a): "us-central1"}


def test_decode_tolerates_legacy_unscoped_entries() -> None:
    net = ipaddress.ip_network("34.100.0.0/24")
    nets, regions = _decode_cached({str(net)})
    assert nets == {net}
    assert regions == {}


def test_refresh_populates_network_regions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    net = ipaddress.ip_network("34.100.0.0/24")

    def fake_gcp() -> tuple[
        set[ipaddress.IPv4Network | ipaddress.IPv6Network], dict[str, str]
    ]:
        return {net}, {str(net): "us-central1"}

    monkeypatch.setattr(
        "guard_core.sync.handlers.cloud_handler.fetch_gcp_ip_ranges", fake_gcp
    )
    manager = CloudManager()
    saved_ranges = dict(manager.ip_ranges)
    saved_regions = dict(manager.network_regions)

    manager._refresh_providers({"GCP"})

    assert manager.network_regions["GCP"] == {str(net): "us-central1"}
    assert manager.is_cloud_ip("34.100.0.5", {"GCP:!us-central1"}) is False

    manager.ip_ranges = saved_ranges
    manager.network_regions = saved_regions


def _fake_gcp_two_regions() -> tuple[
    ipaddress.IPv4Network | ipaddress.IPv6Network,
    ipaddress.IPv4Network | ipaddress.IPv6Network,
    Any,
]:
    net_central = ipaddress.ip_network("34.100.0.0/24")
    net_europe = ipaddress.ip_network("35.200.0.0/24")

    def fake_gcp() -> tuple[
        set[ipaddress.IPv4Network | ipaddress.IPv6Network], dict[str, str]
    ]:
        return {net_central, net_europe}, {
            str(net_central): "us-central1",
            str(net_europe): "europe-west1",
        }

    return net_central, net_europe, fake_gcp


def test_refresh_with_carveout_selector_populates_bare_provider(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    net_central, net_europe, fake_gcp = _fake_gcp_two_regions()
    monkeypatch.setattr(
        "guard_core.sync.handlers.cloud_handler.fetch_gcp_ip_ranges", fake_gcp
    )
    manager = CloudManager()
    saved_ranges = dict(manager.ip_ranges)
    saved_regions = dict(manager.network_regions)

    manager._refresh_providers({"GCP:!us-central1"})

    assert manager.ip_ranges["GCP"] == {net_central, net_europe}
    assert "GCP:!us-central1" not in manager.ip_ranges
    assert manager.is_cloud_ip("35.200.0.5", {"GCP:!us-central1"}) is True
    assert manager.is_cloud_ip("34.100.0.5", {"GCP:!us-central1"}) is False
    assert manager.get_cloud_provider_details("35.200.0.5", {"GCP:!us-central1"}) == (
        "GCP",
        "35.200.0.0/24",
    )

    manager.ip_ranges = saved_ranges
    manager.network_regions = saved_regions


def test_refresh_async_with_carveout_selector_populates_bare_provider(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    net_central, net_europe, fake_gcp = _fake_gcp_two_regions()
    monkeypatch.setattr(
        "guard_core.sync.handlers.cloud_handler.fetch_gcp_ip_ranges", fake_gcp
    )
    manager = CloudManager()
    saved_ranges = dict(manager.ip_ranges)
    saved_regions = dict(manager.network_regions)

    manager.refresh_async({"GCP:!europe-west1"})

    assert manager.ip_ranges["GCP"] == {net_central, net_europe}
    assert "GCP:!europe-west1" not in manager.ip_ranges
    assert manager.is_cloud_ip("34.100.0.5", {"GCP:!europe-west1"}) is True

    manager.ip_ranges = saved_ranges
    manager.network_regions = saved_regions


def test_redis_refresh_with_carveout_selector_populates_bare_provider(
    monkeypatch: pytest.MonkeyPatch,
    security_config_redis: SyncSecurityConfig,
) -> None:
    net_central, net_europe, fake_gcp = _fake_gcp_two_regions()
    monkeypatch.setattr(
        "guard_core.sync.handlers.cloud_handler.fetch_gcp_ip_ranges", fake_gcp
    )
    redis_handler = RedisManager(security_config_redis)
    redis_handler.initialize()
    manager = CloudManager()
    saved_ranges = dict(manager.ip_ranges)
    saved_regions = dict(manager.network_regions)
    saved_redis = manager.redis_handler
    manager.redis_handler = redis_handler

    manager._refresh_providers_via_redis_handler({"GCP:!us-central1"})

    assert manager.ip_ranges["GCP"] == {net_central, net_europe}
    assert "GCP:!us-central1" not in manager.ip_ranges
    assert redis_handler.get_key("cloud_ranges_v2", "GCP")
    assert not redis_handler.get_key("cloud_ranges_v2", "GCP:!us-central1")

    manager.redis_handler = saved_redis
    manager.ip_ranges = saved_ranges
    manager.network_regions = saved_regions
    redis_handler.close()


def test_azure_carveout_exempts_nothing_without_region_metadata() -> None:
    manager = CloudManager()
    saved_ranges = dict(manager.ip_ranges)
    saved_regions = dict(manager.network_regions)
    net = ipaddress.ip_network("20.0.0.0/24")
    manager.ip_ranges["Azure"] = {net}
    manager.network_regions["Azure"] = {}

    assert manager.is_cloud_ip("20.0.0.5", {"Azure:!westus"}) is True
    assert manager.is_cloud_ip("20.0.0.5", {"Azure"}) is True

    manager.ip_ranges = saved_ranges
    manager.network_regions = saved_regions
