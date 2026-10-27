from collections.abc import Generator
from unittest.mock import MagicMock, Mock

import pytest

from guard_core.sync.handlers.ipban_handler import IPBanManager
from tests.fake_agent import mock_agent


@pytest.fixture(autouse=True)
def reset_singleton() -> Generator[None, None, None]:
    IPBanManager._instance = None
    yield
    IPBanManager._instance = None


@pytest.mark.parametrize("text", ["/", "web/xml", "1.2.3.4/33", "not-an-ip", ""])
def test_unban_of_a_string_that_is_not_a_network_changes_no_ban(
    text: str,
) -> None:
    manager = IPBanManager()
    manager.redis_handler = None
    manager.agent_handler = Mock(send_event=MagicMock())
    manager.ban_ip("198.51.100.8", 600, "operator")
    manager.ban_ip("198.51.101.0/24", 600, "operator")
    mock_agent(manager.agent_handler).send_event.reset_mock()

    manager.unban_ip(text)

    assert manager.is_ip_banned("198.51.100.8") is True
    assert manager.is_ip_banned("198.51.101.7") is True
    [event] = mock_agent(manager.agent_handler).send_event.call_args_list
    assert event.args[0].ip_address == text


def test_unban_of_a_valid_cidr_still_lifts_the_network() -> None:
    manager = IPBanManager()
    manager.redis_handler = None
    manager.ban_ip("198.51.101.0/24", 600, "operator")

    manager.unban_ip("198.51.101.0/24")

    assert manager.is_ip_banned("198.51.101.7") is False
