import logging
from unittest.mock import AsyncMock, Mock

import pytest

from guard_core.handlers.ratelimit_handler import (
    _by_ip_request_timestamps,
    check_rate_limit_by_ip,
)
from guard_core.models import SecurityConfig


@pytest.fixture(autouse=True)
def _clean_primitive_store() -> None:
    _by_ip_request_timestamps.clear()


def _config(**settings: object) -> SecurityConfig:
    return SecurityConfig(
        enable_redis=False, rate_limit=2, rate_limit_window=60, **settings
    )


async def _allowed(config: SecurityConfig, *ips: str) -> list[bool]:
    return [await check_rate_limit_by_ip(ip, config) for ip in ips]


async def test_every_spelling_of_one_ipv6_address_shares_one_budget() -> None:
    spellings = ["2001:db8::1", "2001:DB8:0:0:0:0:0:1", "2001:db8:0:0:0:0:0:1"] * 2

    assert await _allowed(_config(), *spellings) == [True, True] + [False] * 4


async def test_an_ipv4_mapped_address_shares_the_budget_of_its_ipv4_form() -> None:
    ips = ["203.0.113.5", "::ffff:203.0.113.5", "203.0.113.5", "::ffff:203.0.113.5"]

    assert await _allowed(_config(), *ips) == [True, True, False, False]


async def test_an_exempt_ip_is_never_limited() -> None:
    config = _config(exempt_ips=["203.0.113.6"])

    assert await _allowed(config, *["203.0.113.6"] * 5) == [True] * 5


async def test_a_whitelisted_ip_is_still_limited() -> None:
    config = _config(whitelist=["203.0.113.7"])

    assert await _allowed(config, *["203.0.113.7"] * 3) == [True, True, False]


async def test_a_block_is_logged_like_the_pipeline_logs_it(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = _config()
    with caplog.at_level(logging.WARNING):
        await _allowed(config, *["203.0.113.8"] * 3)

    messages = [record.getMessage() for record in caplog.records]
    assert any(
        "Rate limit exceeded for IP: 203.0.113.8 (3 requests in 60s window)" in m
        for m in messages
    )


async def test_a_muted_rate_limit_log_stays_quiet(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = _config(muted_check_logs=frozenset({"rate_limit"}))
    with caplog.at_level(logging.WARNING):
        await _allowed(config, *["203.0.113.9"] * 3)

    assert not [r for r in caplog.records if "Rate limit exceeded" in r.getMessage()]


async def test_a_block_sends_one_rate_limited_event_with_the_effective_values() -> None:
    agent = Mock(send_event=AsyncMock())
    config = _config()
    for _ in range(2):
        await check_rate_limit_by_ip("203.0.113.10", config, agent_handler=agent)
    assert agent.send_event.call_count == 0

    assert not await check_rate_limit_by_ip("203.0.113.10", config, agent_handler=agent)

    (call,) = agent.send_event.call_args_list
    event = call.args[0]
    assert event.event_type == "rate_limited"
    assert event.ip_address == "203.0.113.10"
    assert event.action_taken == "request_blocked"
    assert event.metadata == {"request_count": 3, "rate_limit": 2, "window": 60}


async def test_a_passive_block_is_reported_as_logged_only() -> None:
    agent = Mock(send_event=AsyncMock())
    config = _config(passive_mode=True)
    for _ in range(3):
        await check_rate_limit_by_ip("203.0.113.11", config, agent_handler=agent)

    (call,) = agent.send_event.call_args_list
    assert call.args[0].action_taken == "logged_only"


async def test_a_muted_event_type_is_not_sent() -> None:
    agent = Mock(send_event=AsyncMock())
    config = _config(muted_event_types=frozenset({"rate_limited"}))
    for _ in range(3):
        await check_rate_limit_by_ip("203.0.113.12", config, agent_handler=agent)

    assert agent.send_event.call_count == 0
