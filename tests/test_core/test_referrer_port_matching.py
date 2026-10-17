import pytest

from guard_core.core.checks.helpers import is_referrer_domain_allowed

ALLOWED = ["example.com"]


@pytest.mark.parametrize(
    "referrer",
    [
        "https://example.com/a",
        "https://sub.example.com/a",
        "https://example.com:8443/a",
        "https://sub.example.com:8443/a",
        "http://EXAMPLE.com/a",
    ],
)
def test_a_bare_entry_matches_the_host_whatever_the_port(referrer: str) -> None:
    assert is_referrer_domain_allowed(referrer, ALLOWED) is True


def test_a_localhost_dev_origin_with_a_port_matches_a_bare_localhost_entry() -> None:
    assert is_referrer_domain_allowed("http://localhost:3000/", ["localhost"]) is True


@pytest.mark.parametrize(
    ("referrer", "allowed", "expected"),
    [
        ("https://example.com:8443/a", ["https://example.com:8443"], True),
        ("https://example.com:9999/a", ["https://example.com:8443"], False),
        ("https://example.com/a", ["https://example.com:8443"], False),
        ("https://sub.example.com:8443/a", ["example.com:8443"], True),
        ("https://EXAMPLE.com:8443/a", ["example.com:8443"], True),
    ],
)
def test_an_entry_with_a_port_pins_the_port(
    referrer: str, allowed: list[str], expected: bool
) -> None:
    assert is_referrer_domain_allowed(referrer, allowed) is expected
