import ipaddress
import logging
from collections.abc import Generator
from types import SimpleNamespace
from typing import Any

import pytest

from guard_core.models import SecurityConfig
from guard_core.sync._utils import ip_extraction, nat64, sampling
from guard_core.sync._utils.ip_extraction import _canonicalize_ip, _client_identity
from guard_core.sync._utils.nat64 import _decode_nat64_embedded_ipv4
from guard_core.sync.core.checks.factory import build_default_pipeline
from guard_core.sync.core.initialization.handler_initializer import HandlerInitializer
from guard_core.sync.decorators import SecurityDecorator
from tests.test_sync.conftest import SyncMockGuardRequest
from tests.test_sync.test_core.conftest import build_middleware

PUBLIC_V4 = "8.8.8.8"
WELL_KNOWN_PUBLIC = "64:ff9b::808:808"


@pytest.fixture(autouse=True)
def _no_network_specific_prefixes() -> Generator[None, None, None]:
    nat64._non_global_warnings.clear()
    nat64.configure_nat64_prefixes(())
    yield
    nat64.configure_nat64_prefixes(())


def _encode(prefix: str, ipv4: str) -> str:
    network = ipaddress.IPv6Network(prefix)
    value = int(network.network_address)
    octets = int(ipaddress.IPv4Address(ipv4)).to_bytes(4, "big")
    bit_positions = {
        32: [32, 40, 48, 56],
        40: [40, 48, 56, 72],
        48: [48, 56, 72, 80],
        56: [56, 72, 80, 88],
        64: [72, 80, 88, 96],
        96: [96, 104, 112, 120],
    }[network.prefixlen]
    for position, octet in zip(bit_positions, octets, strict=True):
        value |= octet << (128 - position - 8)
    return str(ipaddress.IPv6Address(value))


RFC_6052_EXAMPLES = [
    ("2001:db8::/32", "2001:db8:c000:221::"),
    ("2001:db8:100::/40", "2001:db8:1c0:2:21::"),
    ("2001:db8:122::/48", "2001:db8:122:c000:2:2100::"),
    ("2001:db8:122:300::/56", "2001:db8:122:3c0:0:221::"),
    ("2001:db8:122:344::/64", "2001:db8:122:344:c0:2:2100:0"),
    ("2001:db8:122:344::/96", "2001:db8:122:344::c000:221"),
]


@pytest.mark.parametrize(("prefix", "expected"), RFC_6052_EXAMPLES)
def test_the_encoder_and_the_decoder_follow_the_rfc_6052_table(
    prefix: str, expected: str
) -> None:
    assert _encode(prefix, "192.0.2.33") == expected
    decoded = _decode_nat64_embedded_ipv4(
        ipaddress.IPv6Address(expected), ipaddress.IPv6Network(prefix)
    )
    assert decoded == ipaddress.IPv4Address("192.0.2.33")


def test_a_well_known_prefix_address_with_a_global_ipv4_is_that_ipv4() -> None:
    assert _canonicalize_ip(WELL_KNOWN_PUBLIC) == PUBLIC_V4
    assert _canonicalize_ip("64:ff9b::0808:0808") == PUBLIC_V4


def test_a_well_known_prefix_address_with_a_non_global_ipv4_stays_ipv6() -> None:
    assert _canonicalize_ip("64:ff9b::a00:5") == "64:ff9b::a00:5"
    assert _canonicalize_ip("64:ff9b::c000:201") == "64:ff9b::c000:201"


def test_the_local_use_prefix_stays_per_address_unless_listed() -> None:
    assert _canonicalize_ip("64:ff9b:1::808:808") == "64:ff9b:1::808:808"


def test_a_non_global_embedded_address_warns_once_a_minute(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING, logger="guard_core"):
        for _ in range(3):
            _canonicalize_ip("64:ff9b::a00:5")

    assert len([r for r in caplog.records if "NAT64" in r.getMessage()]) == 1


def test_the_warning_still_fires_once_a_minute_when_the_address_is_cached(
    caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = [1000.0]
    monkeypatch.setattr(sampling, "time", SimpleNamespace(monotonic=lambda: clock[0]))
    parsed: list[str] = []
    real_ip_address = ip_extraction.ip_address

    def counting(value: str) -> object:
        parsed.append(value)
        return real_ip_address(value)

    monkeypatch.setattr(ip_extraction, "ip_address", counting)

    def warnings_after(seconds: float) -> int:
        clock[0] += seconds
        before = len(caplog.records)
        assert _canonicalize_ip("64:ff9b::c000:201") == "64:ff9b::c000:201"
        return len([r for r in caplog.records[before:] if "NAT64" in r.getMessage()])

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        assert warnings_after(0) == 1
        assert warnings_after(30) == 0
        assert warnings_after(31) == 1
        assert warnings_after(1) == 0

    assert len(parsed) == 1


def test_a_changed_prefix_list_is_not_served_from_the_cache() -> None:
    prefix = "2001:db8:122:344::/64"
    address = _encode(prefix, PUBLIC_V4)

    assert _canonicalize_ip(address) == address
    nat64.configure_nat64_prefixes((ipaddress.IPv6Network(prefix),))

    assert _canonicalize_ip(address) == PUBLIC_V4


@pytest.mark.parametrize(("prefix", "_"), RFC_6052_EXAMPLES)
def test_a_configured_prefix_is_decoded_at_its_length(prefix: str, _: str) -> None:
    nat64.configure_nat64_prefixes((ipaddress.IPv6Network(prefix),))

    assert _canonicalize_ip(_encode(prefix, PUBLIC_V4)) == PUBLIC_V4


def test_a_configured_prefix_with_a_non_global_ipv4_stays_ipv6() -> None:
    prefix = "2001:db8:122:344::/64"
    nat64.configure_nat64_prefixes((ipaddress.IPv6Network(prefix),))

    address = _encode(prefix, "10.0.0.5")

    assert _canonicalize_ip(address) == address


def test_an_address_outside_every_prefix_is_untouched() -> None:
    nat64.configure_nat64_prefixes((ipaddress.IPv6Network("2001:db8:122:344::/64"),))

    assert _canonicalize_ip("2001:db8:1::1") == "2001:db8:1::1"
    assert _canonicalize_ip("203.0.113.9") == "203.0.113.9"


def test_the_identity_of_a_decoded_client_is_its_ipv4() -> None:
    assert _client_identity(WELL_KNOWN_PUBLIC, 64) == PUBLIC_V4


def _status(config: SecurityConfig, client_host: str) -> int | None:
    middleware = build_middleware(config, SecurityDecorator(config))
    pipeline = build_default_pipeline(middleware)
    response = pipeline.execute(
        SyncMockGuardRequest(path="/x", client_host=client_host)
    )
    return None if response is None else response.status_code


def _config(**settings: Any) -> SecurityConfig:
    return SecurityConfig(
        enable_redis=False,
        enable_penetration_detection=False,
        enable_rate_limiting=False,
        **settings,
    )


def test_an_ipv4_blacklist_entry_matches_a_translated_client() -> None:
    config = _config(blacklist=["8.8.8.0/24"])

    assert _status(config, WELL_KNOWN_PUBLIC) == 403
    assert _status(config, "8.8.9.9") is None


def test_an_ipv4_whitelist_entry_matches_a_translated_client() -> None:
    config = _config(whitelist=["8.8.8.0/24"])

    assert _status(config, WELL_KNOWN_PUBLIC) is None
    assert _status(config, "64:ff9b::909:909") == 403


def test_a_list_entry_written_as_a_translated_address_matches_the_ipv4() -> None:
    config = _config(blacklist=[WELL_KNOWN_PUBLIC])

    assert _status(config, PUBLIC_V4) == 403


def test_the_field_defaults_to_no_prefixes() -> None:
    assert SecurityConfig(enable_redis=False).nat64_prefixes == []


@pytest.mark.parametrize(
    "prefix", ["2001:db8::/60", "2001:db8::/24", "2001:db8::/128", "10.0.0.0/8", "nope"]
)
def test_an_invalid_prefix_is_a_misconfiguration_at_startup(prefix: str) -> None:
    config = _config(nat64_prefixes=[prefix], fail_on_misconfiguration=True)

    with pytest.raises(ValueError, match="nat64_prefixes"):
        HandlerInitializer(config=config).initialize_redis_handlers()


def test_an_invalid_prefix_only_logs_when_the_flag_is_off_and_is_ignored() -> None:
    config = _config(
        nat64_prefixes=["2001:db8::/60", "2001:db8:122:344::/64"],
        fail_on_misconfiguration=False,
    )

    HandlerInitializer(config=config).initialize_redis_handlers()

    assert _canonicalize_ip(_encode("2001:db8:122:344::/64", PUBLIC_V4)) == PUBLIC_V4


def test_valid_prefixes_are_applied_at_startup() -> None:
    prefix = "2001:db8:122:344::/64"
    config = _config(nat64_prefixes=[prefix], fail_on_misconfiguration=True)

    HandlerInitializer(config=config).initialize_redis_handlers()

    assert _canonicalize_ip(_encode(prefix, PUBLIC_V4)) == PUBLIC_V4
