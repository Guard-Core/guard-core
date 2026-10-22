import pytest

from guard_core.sync._utils.ip_extraction import (
    _canonicalize_ip,
    _canonicalize_plain_ip,
)


@pytest.mark.parametrize(
    ("value", "canonical"),
    [
        ("198.51.100.7", "198.51.100.7"),
        ("[198.51.100.7]", "198.51.100.7"),
        ("not-an-ip", "not-an-ip"),
        ("198.51.100.7%eth0", "198.51.100.7%eth0"),
    ],
)
def test_a_distinct_address_without_a_colon_is_canonicalized_once(
    value: str, canonical: str
) -> None:
    _canonicalize_plain_ip.cache_clear()

    results = [_canonicalize_ip(value) for _ in range(3)]

    assert results == [canonical] * 3
    info = _canonicalize_plain_ip.cache_info()
    assert (info.misses, info.hits) == (1, 2)


@pytest.mark.parametrize(
    ("value", "canonical"),
    [
        ("::ffff:198.51.100.7", "198.51.100.7"),
        ("[2001:db8::1]", "2001:db8::1"),
        ("fe80::1%eth0", "fe80::1"),
        ("64:ff9b::198.51.100.7", "64:ff9b::c633:6407"),
    ],
)
def test_an_address_with_a_colon_is_never_cached(value: str, canonical: str) -> None:
    _canonicalize_plain_ip.cache_clear()

    assert [_canonicalize_ip(value) for _ in range(2)] == [canonical] * 2
    assert _canonicalize_plain_ip.cache_info().currsize == 0
