from collections.abc import Generator
from typing import Any

import pytest

from guard_core._utils import ip_extraction
from guard_core.handlers import ipban_handler
from guard_core.models import SecurityConfig
from tests.test_core.conftest import build_route_pipeline, send_request

PUBLIC_PROXY = "93.184.216.34"
PRIVATE_PROXY = "10.1.2.3"
TRUSTED_PROXY_NETWORK = "198.51.100.0/24"
WHITELISTED_ADDRESS = "192.0.2.200"


@pytest.fixture(autouse=True)
def clear_untrusted_peer_activity() -> Generator[None, None, None]:
    ip_extraction._untrusted_peers.clear()
    yield
    ip_extraction._untrusted_peers.clear()


def _config(**overrides: Any) -> SecurityConfig:
    settings: dict[str, Any] = {
        "enable_redis": False,
        "enable_penetration_detection": False,
        "enable_rate_limiting": False,
        "ban_on_hostile_signals": True,
        "auto_ban_threshold": 2,
        "trusted_proxies": [TRUSTED_PROXY_NETWORK],
    }
    settings.update(overrides)
    return SecurityConfig(**settings)


async def _send(
    config: SecurityConfig, peer: str, forwarded_for_values: list[str]
) -> Any:
    pipeline, middleware, route_id = build_route_pipeline(
        config, lambda d: d.max_request_size(10**6)
    )
    for value in forwarded_for_values:
        await send_request(
            pipeline, route_id, ip=peer, headers={"X-Forwarded-For": value}
        )
    return middleware


async def test_constant_forwarded_for_from_an_untrusted_proxy_is_never_banned() -> None:
    middleware = await _send(_config(), PUBLIC_PROXY, ["198.18.0.9"] * 1000)

    assert middleware.suspicious_request_counts == {}
    assert not await ipban_handler.ip_ban_manager.is_ip_banned(PUBLIC_PROXY)


async def test_untrusted_forwarded_for_warns_once_per_peer_per_window(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level("WARNING", logger="guard_core"):
        await _send(_config(), PUBLIC_PROXY, ["198.18.0.9"] * 50)

    spoof_warnings = [
        record
        for record in caplog.records
        if "Potential IP spoof attempt" in record.getMessage()
    ]
    assert len(spoof_warnings) == 1


async def test_forged_trusted_proxy_forwarded_for_is_counted_and_banned() -> None:
    middleware = await _send(_config(), PUBLIC_PROXY, ["198.51.100.5"] * 2)

    assert PUBLIC_PROXY not in middleware.suspicious_request_counts
    assert await ipban_handler.ip_ban_manager.is_ip_banned(PUBLIC_PROXY)


async def test_forged_route_whitelist_address_is_counted() -> None:
    config = _config(auto_ban_threshold=5)
    pipeline, middleware, route_id = build_route_pipeline(
        config, lambda d: d.require_ip(whitelist=[WHITELISTED_ADDRESS, PUBLIC_PROXY])
    )

    await send_request(
        pipeline,
        route_id,
        ip=PUBLIC_PROXY,
        headers={"X-Forwarded-For": WHITELISTED_ADDRESS},
    )

    assert middleware.suspicious_request_counts[PUBLIC_PROXY] == {"ip_spoofing": 1}


async def test_rotating_forwarded_for_from_a_public_peer_is_never_banned() -> None:
    config = _config(auto_ban_threshold=5, trusted_proxies=["10.0.0.1"])
    middleware = await _send(
        config, PUBLIC_PROXY, [f"198.18.0.{n}" for n in range(1, 41)]
    )

    assert middleware.suspicious_request_counts == {}
    assert not await ipban_handler.ip_ban_manager.is_ip_banned(PUBLIC_PROXY)


async def test_rotating_values_from_a_private_peer_are_never_counted() -> None:
    middleware = await _send(
        _config(auto_ban_threshold=1),
        PRIVATE_PROXY,
        [f"198.18.0.{n}" for n in range(1, 20)] + ["198.51.100.5"],
    )

    assert middleware.suspicious_request_counts == {}
    assert not await ipban_handler.ip_ban_manager.is_ip_banned(PRIVATE_PROXY)


async def test_spoofing_is_not_counted_in_passive_mode() -> None:
    middleware = await _send(
        _config(passive_mode=True), PUBLIC_PROXY, ["198.51.100.5"] * 3
    )

    assert middleware.suspicious_request_counts == {}


def test_tracked_untrusted_peers_stay_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ip_extraction, "_MAX_TRACKED_UNTRUSTED_PEERS", 3)

    config = _config()
    for n in range(10):
        ip_extraction._observe_untrusted_forwarded_for(config, f"93.184.216.{n}")

    assert list(ip_extraction._untrusted_peers.for_app(config).entries) == [
        "93.184.216.7",
        "93.184.216.8",
        "93.184.216.9",
    ]


async def test_unparseable_forwarded_for_entries_are_ignored() -> None:
    middleware = await _send(
        _config(), PUBLIC_PROXY, ["unknown, not-an-ip, 198.18.0.9"] * 3
    )

    assert middleware.suspicious_request_counts == {}


async def test_unparseable_forwarded_for_entry_next_to_a_privileged_one_counts() -> (
    None
):
    middleware = await _send(
        _config(auto_ban_threshold=5), PUBLIC_PROXY, ["unknown, 198.51.100.5"]
    )

    assert middleware.suspicious_request_counts[PUBLIC_PROXY] == {"ip_spoofing": 1}


ROUTE_ALLOWED_ADDRESS = "198.51.100.1"
OTHER_ALLOWED_ADDRESS = "192.0.2.77"


async def _send_to_allow_listed_route(
    config: SecurityConfig, peer: str, claim: str, count: int
) -> tuple[Any, list[int]]:
    pipeline, middleware, route_id = build_route_pipeline(
        config, lambda d: d.require_ip(whitelist=[ROUTE_ALLOWED_ADDRESS])
    )
    codes = []
    for _ in range(count):
        response = await send_request(
            pipeline, route_id, ip=peer, headers={"X-Forwarded-For": claim}
        )
        codes.append(response.status_code if response is not None else 200)
    return middleware, codes


async def test_route_whitelist_claim_is_counted_when_the_allow_list_denies() -> None:
    config = _config(auto_ban_threshold=3, trusted_proxies=["10.0.0.1"])

    middleware, codes = await _send_to_allow_listed_route(
        config, PUBLIC_PROXY, ROUTE_ALLOWED_ADDRESS, 3
    )

    assert codes == [403, 403, 403]
    assert PUBLIC_PROXY not in middleware.suspicious_request_counts
    assert await ipban_handler.ip_ban_manager.is_ip_banned(PUBLIC_PROXY)


async def test_route_whitelist_claim_counts_once_per_denied_request() -> None:
    config = _config(auto_ban_threshold=5, trusted_proxies=["10.0.0.1"])

    middleware, _ = await _send_to_allow_listed_route(
        config, PUBLIC_PROXY, ROUTE_ALLOWED_ADDRESS, 2
    )

    assert middleware.suspicious_request_counts[PUBLIC_PROXY] == {"ip_spoofing": 2}


async def test_route_whitelist_claim_is_counted_when_the_peer_is_allowed() -> None:
    config = _config(auto_ban_threshold=2, trusted_proxies=["10.0.0.1"])
    pipeline, _, route_id = build_route_pipeline(
        config, lambda d: d.require_ip(whitelist=[ROUTE_ALLOWED_ADDRESS, PUBLIC_PROXY])
    )

    for _ in range(2):
        await send_request(
            pipeline,
            route_id,
            ip=PUBLIC_PROXY,
            headers={"X-Forwarded-For": ROUTE_ALLOWED_ADDRESS},
        )

    assert await ipban_handler.ip_ban_manager.is_ip_banned(PUBLIC_PROXY)


async def test_global_whitelist_claim_is_counted_when_the_allow_list_denies() -> None:
    config = _config(
        auto_ban_threshold=3,
        trusted_proxies=["10.0.0.1"],
        whitelist=[WHITELISTED_ADDRESS],
    )

    await _send(config, PUBLIC_PROXY, [WHITELISTED_ADDRESS] * 3)

    assert await ipban_handler.ip_ban_manager.is_ip_banned(PUBLIC_PROXY)


async def test_trusted_proxy_claim_is_counted_on_the_denied_path() -> None:
    config = _config(auto_ban_threshold=3)

    middleware, codes = await _send_to_allow_listed_route(
        config, PUBLIC_PROXY, "198.51.100.5", 3
    )

    assert codes == [403, 403, 403]
    assert await ipban_handler.ip_ban_manager.is_ip_banned(PUBLIC_PROXY)


async def test_plain_claim_on_a_denied_request_is_never_counted() -> None:
    config = _config(auto_ban_threshold=1, trusted_proxies=["10.0.0.1"])

    middleware, codes = await _send_to_allow_listed_route(
        config, PUBLIC_PROXY, "198.18.0.9", 5
    )

    assert codes == [403] * 5
    assert middleware.suspicious_request_counts == {}
    assert not await ipban_handler.ip_ban_manager.is_ip_banned(PUBLIC_PROXY)


async def test_private_peer_claim_on_a_denied_request_is_never_counted() -> None:
    config = _config(auto_ban_threshold=1, trusted_proxies=["10.0.0.1"])

    middleware, codes = await _send_to_allow_listed_route(
        config, PRIVATE_PROXY, ROUTE_ALLOWED_ADDRESS, 5
    )

    assert codes == [403] * 5
    assert middleware.suspicious_request_counts == {}
    assert not await ipban_handler.ip_ban_manager.is_ip_banned(PRIVATE_PROXY)


async def test_an_already_banned_peer_is_not_counted_again() -> None:
    config = _config(auto_ban_threshold=1, trusted_proxies=["10.0.0.1"])
    middleware, _ = await _send_to_allow_listed_route(
        config, PUBLIC_PROXY, ROUTE_ALLOWED_ADDRESS, 1
    )
    counted = dict(middleware.suspicious_request_counts)

    pipeline, _, route_id = build_route_pipeline(
        config, lambda d: d.require_ip(whitelist=[ROUTE_ALLOWED_ADDRESS])
    )
    await send_request(
        pipeline,
        route_id,
        ip=PUBLIC_PROXY,
        headers={"X-Forwarded-For": ROUTE_ALLOWED_ADDRESS},
    )

    assert counted == {}
    assert middleware.suspicious_request_counts == {}
