import logging
from unittest.mock import MagicMock, Mock

import pytest

from guard_core.models import SecurityConfig
from guard_core.sync.handlers.ratelimit_handler import (
    _by_ip_request_timestamps,
    check_rate_limit_by_ip,
)


@pytest.fixture(autouse=True)
def _clean_primitive_store() -> None:
    _by_ip_request_timestamps.clear()


def _config(**settings: object) -> SecurityConfig:
    return SecurityConfig(
        enable_redis=False, rate_limit=2, rate_limit_window=60, **settings
    )


def _allowed(config: SecurityConfig, *ips: str) -> list[bool]:
    return [check_rate_limit_by_ip(ip, config) for ip in ips]


def test_every_spelling_of_one_ipv6_address_shares_one_budget() -> None:
    spellings = ["2001:db8::1", "2001:DB8:0:0:0:0:0:1", "2001:db8:0:0:0:0:0:1"] * 2

    assert _allowed(_config(), *spellings) == [True, True] + [False] * 4


def test_an_ipv4_mapped_address_shares_the_budget_of_its_ipv4_form() -> None:
    ips = ["203.0.113.5", "::ffff:203.0.113.5", "203.0.113.5", "::ffff:203.0.113.5"]

    assert _allowed(_config(), *ips) == [True, True, False, False]


def test_an_exempt_ip_is_never_limited() -> None:
    config = _config(exempt_ips=["203.0.113.6"])

    assert _allowed(config, *["203.0.113.6"] * 5) == [True] * 5


def test_a_whitelisted_ip_is_still_limited() -> None:
    config = _config(whitelist=["203.0.113.7"])

    assert _allowed(config, *["203.0.113.7"] * 3) == [True, True, False]


def test_a_block_is_logged_like_the_pipeline_logs_it(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = _config()
    with caplog.at_level(logging.WARNING):
        _allowed(config, *["203.0.113.8"] * 3)

    messages = [record.getMessage() for record in caplog.records]
    assert any(
        "Rate limit exceeded for IP: 203.0.113.8 (3 requests in 60s window)" in m
        for m in messages
    )


def test_a_muted_rate_limit_log_stays_quiet(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = _config(muted_check_logs=frozenset({"rate_limit"}))
    with caplog.at_level(logging.WARNING):
        _allowed(config, *["203.0.113.9"] * 3)

    assert not [r for r in caplog.records if "Rate limit exceeded" in r.getMessage()]


def test_a_block_sends_one_rate_limited_event_with_the_effective_values() -> None:
    agent = Mock(send_event=MagicMock())
    config = _config()
    for _ in range(2):
        check_rate_limit_by_ip("203.0.113.10", config, agent_handler=agent)
    assert agent.send_event.call_count == 0

    assert not check_rate_limit_by_ip("203.0.113.10", config, agent_handler=agent)

    (call,) = agent.send_event.call_args_list
    event = call.args[0]
    assert event.event_type == "rate_limited"
    assert event.ip_address == "203.0.113.10"
    assert event.action_taken == "request_blocked"
    assert event.metadata == {"request_count": 3, "rate_limit": 2, "window": 60}


def test_a_passive_block_is_reported_as_logged_only() -> None:
    agent = Mock(send_event=MagicMock())
    config = _config(passive_mode=True)
    for _ in range(3):
        check_rate_limit_by_ip("203.0.113.11", config, agent_handler=agent)

    (call,) = agent.send_event.call_args_list
    assert call.args[0].action_taken == "logged_only"


def test_a_muted_event_type_is_not_sent() -> None:
    agent = Mock(send_event=MagicMock())
    config = _config(muted_event_types=frozenset({"rate_limited"}))
    for _ in range(3):
        check_rate_limit_by_ip("203.0.113.12", config, agent_handler=agent)

    assert agent.send_event.call_count == 0
