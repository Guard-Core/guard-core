import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync._utils import ip_extraction
from guard_core.sync._utils.ip_extraction import _handle_untrusted_proxy
from tests.test_sync.conftest import SyncMockGuardRequest


@pytest.fixture
def sampled_peers(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    seen: list[str] = []

    def observe(config: object, peer: str) -> tuple[bool, int]:
        seen.append(peer)
        return False, 0

    monkeypatch.setattr(ip_extraction, "_observe_untrusted_forwarded_for", observe)
    return seen


def _call(address: str, config: SyncSecurityConfig) -> None:
    _handle_untrusted_proxy(
        SyncMockGuardRequest(client_host=address),
        address,
        address,
        "1.2.3.4",
        None,
        config,
    )


def test_a_client_rotating_inside_its_ipv6_prefix_is_one_sampled_peer(
    sampled_peers: list[str],
) -> None:
    config = SyncSecurityConfig()

    for index in range(20):
        _call(f"2606:4700:1:2:{index:x}::{index + 1:x}", config)

    assert len(set(sampled_peers)) == 1


def test_clients_in_different_prefixes_are_different_peers(
    sampled_peers: list[str],
) -> None:
    config = SyncSecurityConfig()

    _call("2606:4700:1:2::1", config)
    _call("2606:4700:1:3::1", config)

    assert len(set(sampled_peers)) == 2


def test_an_ipv4_peer_is_sampled_by_its_address(sampled_peers: list[str]) -> None:
    _call("203.0.113.5", SyncSecurityConfig())

    assert sampled_peers == ["203.0.113.5"]
