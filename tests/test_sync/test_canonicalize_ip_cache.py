from ipaddress import IPv4Address, IPv6Address

import pytest

from guard_core.sync._utils import ip_extraction
from guard_core.sync._utils.ip_extraction import _canonicalize_ip


def _count_parses(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    parsed: list[str] = []
    real_ip_address = ip_extraction.ip_address

    def counting(value: str) -> IPv4Address | IPv6Address:
        parsed.append(value)
        return real_ip_address(value)

    monkeypatch.setattr(ip_extraction, "ip_address", counting)
    return parsed


@pytest.mark.parametrize(
    ("value", "canonical"),
    [
        ("198.51.100.7", "198.51.100.7"),
        ("[198.51.100.7]", "198.51.100.7"),
        ("not-an-ip", "not-an-ip"),
        ("198.51.100.7%eth0", "198.51.100.7%eth0"),
        ("::ffff:198.51.100.7", "198.51.100.7"),
        ("[2001:db8::1]", "2001:db8::1"),
        ("2001:db8:0:0:0:0:0:1", "2001:db8::1"),
        ("fe80::1%eth0", "fe80::1"),
        ("64:ff9b::198.51.100.7", "64:ff9b::c633:6407"),
        ("64:ff9b::808:808", "8.8.8.8"),
        ("not:an:ip", "not:an:ip"),
    ],
)
def test_a_distinct_address_is_canonicalized_once(
    value: str, canonical: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    ip_extraction._canonical_ip_text_and_nat64_warning.cache_clear()
    parsed = _count_parses(monkeypatch)

    results = [_canonicalize_ip(value) for _ in range(3)]

    assert results == [canonical] * 3
    assert len(parsed) == 1
