import pytest

from guard_core._utils import ip_extraction
from guard_core._utils.ip_extraction import _handle_untrusted_proxy
from guard_core.models import SecurityConfig
from tests.conftest import MockGuardRequest


@pytest.fixture
def sampled_peers(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    seen: list[str] = []

    def observe(config: object, peer: str) -> tuple[bool, int]:
        seen.append(peer)
        return False, 0

    monkeypatch.setattr(ip_extraction, "_observe_untrusted_forwarded_for", observe)
    return seen


async def _call(address: str, config: SecurityConfig) -> None:
    await _handle_untrusted_proxy(
        MockGuardRequest(client_host=address), address, address, "1.2.3.4", None, config
    )


async def test_a_client_rotating_inside_its_ipv6_prefix_is_one_sampled_peer(
    sampled_peers: list[str],
) -> None:
    config = SecurityConfig()

    for index in range(20):
        await _call(f"2606:4700:1:2:{index:x}::{index + 1:x}", config)

    assert len(set(sampled_peers)) == 1


async def test_clients_in_different_prefixes_are_different_peers(
    sampled_peers: list[str],
) -> None:
    config = SecurityConfig()

    await _call("2606:4700:1:2::1", config)
    await _call("2606:4700:1:3::1", config)

    assert len(set(sampled_peers)) == 2


async def test_an_ipv4_peer_is_sampled_by_its_address(sampled_peers: list[str]) -> None:
    await _call("203.0.113.5", SecurityConfig())

    assert sampled_peers == ["203.0.113.5"]
