import os
from collections.abc import Generator
from typing import Any
from unittest.mock import MagicMock, Mock

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.handlers.ipban_handler import IPBanManager
from guard_core.sync.handlers.redis_handler import RedisManager
from tests.fake_agent import mock_agent
from tests.test_sync.conftest import suite_redis_prefix

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379")


@pytest.fixture(autouse=True)
def reset_singleton() -> Generator[None, None, None]:
    IPBanManager._instance = None
    yield
    IPBanManager._instance = None


@pytest.fixture
def live_redis() -> Generator[RedisManager, None]:
    config = SyncSecurityConfig(
        redis_url=REDIS_URL, redis_prefix=suite_redis_prefix("wp6-cidr")
    )
    manager = RedisManager(config)
    manager.initialize()
    yield manager
    manager.delete_pattern("*")
    manager.close()


def _events(manager: IPBanManager) -> list[Any]:
    return [
        call.args[0]
        for call in mock_agent(manager.agent_handler).send_event.call_args_list
    ]


def test_a_cidr_ban_sends_an_ip_banned_event() -> None:
    manager = IPBanManager()
    manager.redis_handler = None
    manager.agent_handler = Mock(send_event=MagicMock())

    manager.ban_ip("198.51.101.0/24", 600, "operator")

    [event] = _events(manager)
    assert event.event_type == "ip_banned"
    assert event.ip_address == "198.51.101.0/24"
    assert event.action_taken == "banned"
    assert event.reason == "operator"
    assert event.metadata == {"duration": 600}


def test_unbanning_a_cidr_lifts_the_ban_and_sends_an_unban_event() -> None:
    manager = IPBanManager()
    manager.redis_handler = None
    manager.ban_ip("198.51.101.0/24", 600, "operator")
    manager.agent_handler = Mock(send_event=MagicMock())

    manager.unban_ip("198.51.101.0/24")

    assert manager.is_ip_banned("198.51.101.7") is False
    [event] = _events(manager)
    assert event.event_type == "ip_unbanned"
    assert event.ip_address == "198.51.101.0/24"


def test_a_manual_unban_reports_its_own_reason() -> None:
    manager = IPBanManager()
    manager.redis_handler = None
    manager.agent_handler = Mock(send_event=MagicMock())
    manager.ban_ip("198.51.100.8", 600, "operator")
    mock_agent(manager.agent_handler).send_event.reset_mock()

    manager.unban_ip("198.51.100.8")
    manager.unban_ip("198.51.100.9", reason="dynamic_rule_whitelist")

    reasons = [event.reason for event in _events(manager)]
    assert reasons == ["manual_unban", "dynamic_rule_whitelist"]


def test_reset_clears_redis_cidr_bans_as_well_as_exact_bans(
    live_redis: RedisManager,
) -> None:
    manager = IPBanManager()
    manager.redis_handler = live_redis
    manager.ban_ip("198.51.101.0/24", 600, "operator")
    manager.ban_ip("198.51.100.8", 600, "operator")
    assert live_redis.keys("banned_*:*")

    manager.reset()

    assert not live_redis.keys("banned_*:*")
