import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.handlers._dynamic_rule_plan import _classify_exempt_entry
from guard_core.sync.utils import is_ip_allowed


@pytest.mark.parametrize(
    ("entry", "stored"),
    [
        ("::ffff:1.2.3.0/120", "1.2.3.0/24"),
        ("::ffff:1.2.3.4/128", "1.2.3.4/32"),
        ("::ffff:1.0.0.0/104", "1.0.0.0/8"),
        ("::ffff:0:0/96", "0.0.0.0/0"),
        ("2001:db8::/32", "2001:db8::/32"),
        ("1.2.3.0/24", "1.2.3.0/24"),
    ],
)
def test_the_validators_unwrap_a_mapped_network(entry: str, stored: str) -> None:
    assert SyncSecurityConfig(blacklist=[entry], whitelist=None).blacklist == (stored,)
    assert SyncSecurityConfig(trusted_proxies=[entry]).trusted_proxies == (stored,)


@pytest.mark.parametrize(
    "entry", ["::ffff:1.2.3.0/120", "::ffff:1.2.3.4/128", "::ffff:1.0.0.0/104"]
)
def test_a_mapped_blacklist_entry_blocks_the_plain_ipv4_client(
    entry: str,
) -> None:
    config = SyncSecurityConfig(blacklist=[entry], whitelist=None)

    assert is_ip_allowed("1.2.3.4", config) is False
    assert is_ip_allowed("::ffff:1.2.3.4", config) is False
    assert is_ip_allowed("9.9.9.9", config) is True


def test_a_mapped_whitelist_entry_admits_the_plain_ipv4_client() -> None:
    config = SyncSecurityConfig(whitelist=["::ffff:1.2.3.0/120"])

    assert is_ip_allowed("1.2.3.4", config) is True
    assert is_ip_allowed("9.9.9.9", config) is False


@pytest.mark.parametrize(
    "entry",
    [
        "::ffff:127.0.0.1",
        "::ffff:127.0.0.0/104",
        "::ffff:0:0/96",
        "64:ff9b::7f00:1",
        "64:ff9b::7f00:0/104",
        "127.0.0.1",
        "::1",
    ],
)
def test_a_mapped_or_nat64_loopback_exempt_entry_is_refused(entry: str) -> None:
    assert _classify_exempt_entry(entry) == (None, "loopback")


def test_a_mapped_exempt_entry_is_stored_as_ipv4() -> None:
    assert _classify_exempt_entry("::ffff:8.8.8.8") == ("8.8.8.8", None)
    assert _classify_exempt_entry("::ffff:8.8.8.0/120") == ("8.8.8.0/24", None)
