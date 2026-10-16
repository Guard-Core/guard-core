import pytest

from guard_core.models import SecurityConfig
from guard_core.sync._utils.ip_extraction import _is_trusted_proxy, extract_client_ip
from tests.test_sync.conftest import SyncMockGuardRequest

CLIENT = "203.0.113.9"


@pytest.mark.parametrize(
    "peer",
    [
        "10.0.0.5",
        "::ffff:10.0.0.5",
        "::FFFF:10.0.0.5",
        "[::ffff:10.0.0.5]",
        "::ffff:a00:5",
    ],
)
@pytest.mark.parametrize("proxies", [["10.0.0.5"], ["10.0.0.0/8"]])
def test_mapped_and_cased_peers_match_trusted_proxies(
    peer: str, proxies: list[str]
) -> None:
    config = SecurityConfig(trusted_proxies=proxies, enable_redis=False)
    request = SyncMockGuardRequest(
        headers={"X-Forwarded-For": CLIENT}, client_host=peer
    )

    assert extract_client_ip(request, config) == CLIENT


def test_zoned_peer_matches_trusted_proxy() -> None:
    assert _is_trusted_proxy("fe80::1%eth0", ["fe80::/10"]) is True
    assert _is_trusted_proxy("FE80::1%en0", ["fe80::1"]) is True


def test_proxy_entry_is_canonicalized_too() -> None:
    assert _is_trusted_proxy("10.0.0.5", ["::ffff:10.0.0.5"]) is True


@pytest.mark.parametrize("peer", ["not-an-ip", "", "10.0.0.6", "::ffff:10.0.0.6"])
def test_non_matching_or_malformed_peer_is_untrusted(peer: str) -> None:
    assert _is_trusted_proxy(peer, ["10.0.0.5", "192.168.0.0/16"]) is False


def test_malformed_proxy_entry_never_matches() -> None:
    assert _is_trusted_proxy("10.0.0.5", ["10.0.0.0/99", "not-an-ip"]) is False
