"""The spoof check and the spoof message look at a bounded number of X-Forwarded-For
entries, bounded before any entry is parsed (a 16 KiB header holds about 2,000)."""

import random
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

from guard_core.models import SecurityConfig
from guard_core.sync._utils import ip_extraction
from guard_core.sync._utils.ip_extraction import (
    MAX_INSPECTED_FORWARDED_ENTRIES,
    _bounded_forwarded_entries,
    _display_forwarded_chain,
    _forwarded_header_candidate_addr,
    _is_trusted_proxy,
    _strip_forwarded_entry_port,
    extract_client_ip,
    forwarded_for_addresses,
)
from guard_core.sync.core.checks.implementations.ip_security import IpSecurityCheck
from guard_core.sync.decorators.base import RouteConfig
from guard_core.sync.utils import _ip_in_list
from tests.test_sync.conftest import SyncMockGuardRequest

BOUND = MAX_INSPECTED_FORWARDED_ENTRIES
LONG = ",".join(f"8.{index // 256}.{index % 256}.1" for index in range(2048))
WHITELIST = ["203.0.113.0/24", "198.51.100.77"]
PROXIES = ["10.0.0.0/8", "2001:db8:aaaa::/48"]
POOL = [
    "8.8.8.8",
    "1.1.1.1",
    "203.0.113.5",
    "198.51.100.77",
    "10.1.2.3",
    "2001:db8:aaaa::1",
    "[2001:db8::1]",
    "8.8.4.4:443",
    "bad",
    "",
    "unknown",
]


def old_display(value: str) -> str:
    displayed = []
    for part in value.split(","):
        candidate = _strip_forwarded_entry_port(part.strip())
        if _forwarded_header_candidate_addr(candidate) is not None:
            displayed.append(part)
        else:
            displayed.append("[REDACTED]")
    return ",".join(displayed)


def old_claims(config: Any, forwarded_for: str, route_whitelist: Any) -> bool:
    for entry in forwarded_for.split(","):
        address = ip_extraction._peer_address_for_matching(
            _strip_forwarded_entry_port(entry.strip())
        )
        if address is None:
            continue
        text = str(address)
        if (
            _is_trusted_proxy(text, config.trusted_proxies)
            or _ip_in_list(address, text, config.whitelist)
            or (
                route_whitelist is not None
                and _ip_in_list(address, text, route_whitelist)
            )
        ):
            return True
    return False


def _check() -> Any:
    config = SecurityConfig(
        enable_redis=False, trusted_proxies=PROXIES, whitelist=WHITELIST
    )
    return SimpleNamespace(config=config)


def test_entries_are_bounded_before_parsing_and_the_rest_is_counted() -> None:
    entries, more = _bounded_forwarded_entries(LONG)

    assert len(entries) == BOUND
    assert more == 2048 - BOUND
    assert _bounded_forwarded_entries("1.1.1.1,2.2.2.2") == (
        ["1.1.1.1", "2.2.2.2"],
        0,
    )


def test_a_long_header_parses_at_most_the_bound(monkeypatch: Any) -> None:
    calls: list[str] = []
    original = ip_extraction._peer_address_for_matching

    def counting(value: str) -> Any:
        calls.append(value)
        return original(value)

    monkeypatch.setattr(ip_extraction, "_peer_address_for_matching", counting)

    forwarded_for_addresses(LONG)

    assert len(calls) == BOUND


def test_the_display_of_a_long_chain_is_bounded_and_names_the_rest() -> None:
    shown = _display_forwarded_chain(LONG)

    assert shown.endswith(f", ... and {2048 - BOUND} more")
    assert len(shown) < 1000


def test_the_display_of_a_chain_within_the_bound_is_unchanged() -> None:
    generator = random.Random(7)
    for _ in range(300):
        chain = ",".join(generator.choices(POOL, k=generator.randint(1, BOUND)))
        assert _display_forwarded_chain(chain) == old_display(chain)


def test_the_spoof_verdict_is_unchanged_for_every_chain_within_the_bound() -> None:
    check = _check()
    claims = IpSecurityCheck._forwarded_for_claims_privileged_address
    generator = random.Random(20261019)
    for _ in range(600):
        chain = ",".join(generator.choices(POOL, k=generator.randint(1, BOUND)))
        route_whitelist = generator.choice([None, ["8.8.4.0/24"]])
        route = RouteConfig()
        route.ip_whitelist = route_whitelist
        expected = old_claims(check.config, chain, route_whitelist)
        assert claims(check, chain, route) == expected, chain


def test_a_claim_past_the_bound_is_never_inspected() -> None:
    check = _check()
    chain = ",".join(["8.8.8.8"] * BOUND + ["203.0.113.5"])

    assert old_claims(check.config, chain, None) is True
    assert (
        IpSecurityCheck._forwarded_for_claims_privileged_address(check, chain, None)
        is False
    )


def test_the_spoof_message_and_event_name_the_truncation() -> None:
    agent = MagicMock()
    agent.send_event = MagicMock()
    config = SecurityConfig(enable_redis=False, trusted_proxies=["10.0.0.5"])
    request = SyncMockGuardRequest(
        client_host="198.51.100.9", headers={"X-Forwarded-For": LONG}
    )

    extract_client_ip(request, config, agent)

    event = agent.send_event.call_args_list[0].args[0]
    assert f"and {2048 - BOUND} more" in event.reason
    assert len(event.reason) < 1200
