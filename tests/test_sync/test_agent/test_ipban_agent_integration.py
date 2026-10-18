import logging
from collections.abc import Generator
from typing import Any
from unittest.mock import MagicMock

import pytest

from guard_core.sync.handlers.ipban_handler import IPBanManager
from tests.test_sync.ipban_redis_fake import fake_ban_redis


@pytest.fixture
def cleanup_ipban_singleton() -> Generator[Any, Any, Any]:
    IPBanManager._instance = None
    yield
    IPBanManager._instance = None


def test_initialize_agent(cleanup_ipban_singleton: None) -> None:
    IPBanManager._instance = None

    manager = IPBanManager()
    mock_agent = MagicMock()

    manager.initialize_agent(mock_agent)

    assert manager.agent_handler is mock_agent


def test_send_ban_event_success(cleanup_ipban_singleton: None) -> None:
    IPBanManager._instance = None

    manager = IPBanManager()
    manager.agent_handler = MagicMock()

    manager.ban_ip("192.168.1.100", 3600, "test_reason")

    manager.agent_handler.send_event.assert_called_once()
    sent_event = manager.agent_handler.send_event.call_args[0][0]

    assert sent_event.event_type == "ip_banned"
    assert sent_event.ip_address == "192.168.1.100"
    assert sent_event.action_taken == "banned"
    assert sent_event.reason == "test_reason"
    assert sent_event.metadata["duration"] == 3600
    assert sent_event.handler_name == "ip_ban"


def test_send_ban_event_failure(
    caplog: pytest.LogCaptureFixture, cleanup_ipban_singleton: None
) -> None:
    IPBanManager._instance = None

    manager = IPBanManager()
    manager.agent_handler = MagicMock()
    manager.agent_handler.send_event.side_effect = Exception("Network error")

    with caplog.at_level(logging.ERROR):
        manager.ban_ip("192.168.1.101", 3600, "test_reason")

    assert "Failed to send ban event to agent: Network error" in caplog.text


def test_unban_ip_with_agent(cleanup_ipban_singleton: None) -> None:
    IPBanManager._instance = None

    manager = IPBanManager()
    manager.agent_handler = MagicMock()
    manager.redis_handler = fake_ban_redis(None)

    manager.ban_ip("192.168.1.103", 3600, "test_reason")
    manager.agent_handler.send_event.reset_mock()

    manager.unban_ip("192.168.1.103")

    assert manager.is_ip_banned("192.168.1.103") is False

    manager.redis_handler.delete.assert_any_call("banned_ips", "192.168.1.103")

    manager.agent_handler.send_event.assert_called_once()


def test_send_unban_event_success(cleanup_ipban_singleton: None) -> None:
    IPBanManager._instance = None

    manager = IPBanManager()
    manager.agent_handler = MagicMock()

    manager.ban_ip("172.16.0.1", 1800, "test")
    manager.agent_handler.send_event.reset_mock()

    manager.unban_ip("172.16.0.1")

    sent_event = manager.agent_handler.send_event.call_args[0][0]
    assert sent_event.event_type == "ip_unbanned"
    assert sent_event.ip_address == "172.16.0.1"
    assert sent_event.action_taken == "unbanned"
    assert sent_event.reason == "manual_unban"
    assert sent_event.metadata == {"action": "unban"}
    assert sent_event.handler_name == "ip_ban"


def test_send_unban_event_failure(
    caplog: pytest.LogCaptureFixture, cleanup_ipban_singleton: None
) -> None:
    IPBanManager._instance = None

    manager = IPBanManager()
    manager.agent_handler = MagicMock()

    manager.agent_handler.send_event.side_effect = [
        None,
        Exception("Connection timeout"),
    ]

    manager.ban_ip("192.168.1.105", 3600, "test_reason")

    with caplog.at_level(logging.ERROR):
        manager.unban_ip("192.168.1.105")

    assert "Failed to send unban event to agent: Connection timeout" in caplog.text
