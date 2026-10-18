import logging
from collections.abc import Generator
from typing import Any
from unittest.mock import MagicMock

import pytest

from guard_core.models import SecurityConfig
from guard_core.sync.core.checks.factory import build_default_pipeline
from guard_core.sync.decorators import SecurityDecorator
from guard_core.sync.handlers.ipban_handler import ip_ban_manager
from guard_core.sync.utils import extract_client_ip
from tests.test_sync.conftest import SyncMockGuardRequest
from tests.test_sync.test_core.conftest import build_middleware

PEER = "10.0.0.5"
MALFORMED_IDENTITY = f"malformed-xff@{PEER}"


@pytest.fixture(autouse=True)
def _fresh_ban_store() -> Generator[None, None]:
    ip_ban_manager.banned_ips.clear()
    ip_ban_manager.redis_handler = None
    yield
    ip_ban_manager.banned_ips.clear()


def _config(**settings: Any) -> SecurityConfig:
    defaults: dict[str, Any] = {
        "enable_redis": False,
        "enable_penetration_detection": False,
        "enable_rate_limiting": False,
        "trusted_proxies": [PEER],
    }
    return SecurityConfig(**{**defaults, **settings})


def _request(forwarded_for: str, client_host: str = PEER) -> SyncMockGuardRequest:
    return SyncMockGuardRequest(
        path="/x", client_host=client_host, headers={"X-Forwarded-For": forwarded_for}
    )


def _status(config: SecurityConfig, forwarded_for: str) -> int | None:
    middleware = build_middleware(config, SecurityDecorator(config))
    response = build_default_pipeline(middleware).execute(_request(forwarded_for))
    return None if response is None else response.status_code


@pytest.mark.parametrize("zone", ["a", "b", "eth0"])
def test_a_zone_id_in_forwarded_for_is_not_part_of_the_identity(
    zone: str,
) -> None:
    request = _request(f"fe80::1%{zone}")

    assert extract_client_ip(request, _config()) == "fe80::1"


def test_a_zoned_peer_resolves_to_its_unzoned_identity() -> None:
    config = SecurityConfig(enable_redis=False)
    request = SyncMockGuardRequest(client_host="fe80::1%eth0")

    assert extract_client_ip(request, config) == "fe80::1"


@pytest.mark.parametrize("forwarded_for", ["9.9.9.9,", ",", "9.9.9.9, not-an-ip"])
def test_an_unparsable_entry_at_the_trusted_depth_answers_400(
    forwarded_for: str,
) -> None:
    assert _status(_config(), forwarded_for) == 400


def test_the_400_gives_no_strike_and_no_ban() -> None:
    config = _config(ban_on_hostile_signals=True, auto_ban_threshold=1)
    middleware = build_middleware(config, SecurityDecorator(config))
    pipeline = build_default_pipeline(middleware)

    statuses = []
    for _ in range(3):
        response = pipeline.execute(_request("9.9.9.9,"))
        statuses.append(None if response is None else response.status_code)

    assert statuses == [400, 400, 400]
    assert not ip_ban_manager.is_ip_banned(MALFORMED_IDENTITY)


def test_without_fail_secure_the_malformed_chain_gets_its_own_identity() -> None:
    request = _request("9.9.9.9,")

    identity = extract_client_ip(request, _config(fail_secure=False))

    assert identity == MALFORMED_IDENTITY


def test_without_fail_secure_the_request_passes_under_its_own_identity() -> None:
    assert _status(_config(fail_secure=False), "9.9.9.9,") is None


def test_the_malformed_identity_can_be_banned_and_is_then_denied() -> None:
    config = _config(fail_secure=False)

    assert ip_ban_manager.ban_ip(MALFORMED_IDENTITY, 60, "test") is True

    assert ip_ban_manager.is_ip_banned(MALFORMED_IDENTITY) is True
    assert _status(config, "9.9.9.9,") == 403
    assert _status(config, "9.9.9.9") is None


def test_the_malformed_identity_is_rate_limited_and_auto_banned_per_peer() -> None:
    config = _config(
        fail_secure=False,
        enable_rate_limiting=True,
        rate_limit=1,
        rate_limit_window=60,
        enable_rate_limit_auto_ban=True,
        auto_ban_threshold=2,
    )
    middleware = build_middleware(config, SecurityDecorator(config))
    pipeline = build_default_pipeline(middleware)

    statuses = []
    for _ in range(5):
        response = pipeline.execute(_request("9.9.9.9,"))
        statuses.append(None if response is None else response.status_code)

    assert statuses[:2] == [None, 429]
    assert 403 in statuses
    assert ip_ban_manager.is_ip_banned(MALFORMED_IDENTITY)


def test_a_whitelist_denies_the_malformed_identity_like_an_unknown_client() -> None:
    config = _config(fail_secure=False, whitelist=["203.0.113.0/24"])

    assert _status(config, "9.9.9.9,") == 403


def test_the_warning_is_sampled_per_peer(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = _config(fail_secure=False)

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        for _ in range(5):
            extract_client_ip(_request("9.9.9.9,"), config)

    messages = [r.message for r in caplog.records if "X-Forwarded-For" in r.message]
    assert len(messages) == 1
    assert PEER in messages[0]


def test_an_event_names_the_peer_and_the_action() -> None:
    agent = MagicMock()
    agent.send_event = MagicMock()

    extract_client_ip(_request("9.9.9.9,"), _config(), agent)

    event = agent.send_event.call_args.args[0]
    assert event.event_type == "suspicious_request"
    assert event.action_taken == "malformed_forwarded_for"
    assert event.ip_address == PEER


def test_a_well_formed_chain_and_an_absent_header_are_unchanged() -> None:
    config = _config()

    assert extract_client_ip(_request("9.9.9.9"), config) == "9.9.9.9"
    absent = SyncMockGuardRequest(client_host=PEER)
    assert extract_client_ip(absent, config) == PEER
