import logging
from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest

from guard_core.sync.utils import send_agent_event


@pytest.fixture(autouse=True)
def patch_security_event() -> object:
    with patch("guard_core.sync.utils.SecurityEvent", create=True) as mock_event:
        from guard_agent.models import SecurityEvent

        mock_event.side_effect = SecurityEvent
        yield


def test_send_agent_event_no_handler() -> None:
    send_agent_event(
        agent_handler=None,
        event_type="test_event",
        ip_address="192.168.1.1",
        action_taken="test_action",
        reason="test reason",
    )


def test_send_agent_event_success_without_request() -> None:
    mock_agent = MagicMock()

    send_agent_event(
        agent_handler=mock_agent,
        event_type="ip_banned",
        ip_address="192.168.1.100",
        action_taken="banned",
        reason="Suspicious activity detected",
        metadata={"extra_field": "extra_value"},
    )

    mock_agent.send_event.assert_called_once()
    sent_event = mock_agent.send_event.call_args[0][0]

    assert sent_event.event_type == "ip_banned"
    assert sent_event.ip_address == "192.168.1.100"
    assert sent_event.action_taken == "banned"
    assert sent_event.reason == "Suspicious activity detected"
    assert sent_event.endpoint is None
    assert sent_event.method is None
    assert sent_event.user_agent is None
    assert sent_event.country is None
    assert sent_event.metadata == {"extra_field": "extra_value"}
    assert isinstance(sent_event.timestamp, datetime)


def test_send_agent_event_exception_handling(
    caplog: pytest.LogCaptureFixture,
) -> None:
    mock_agent = MagicMock()
    mock_agent.send_event.side_effect = Exception("Network error")

    caplog.set_level(logging.ERROR)

    send_agent_event(
        agent_handler=mock_agent,
        event_type="suspicious_request",
        ip_address="192.168.1.100",
        action_taken="test_action",
        reason="test reason",
    )

    assert "Failed to send agent event: Network error" in caplog.text


def test_send_agent_event_with_request() -> None:
    mock_agent = MagicMock()

    mock_request = MagicMock()
    mock_request.url_path = "/api/v1/test"
    mock_request.method = "GET"
    mock_request.headers = MagicMock()
    mock_request.headers.get = MagicMock(return_value="TestBrowser/1.0")

    send_agent_event(
        agent_handler=mock_agent,
        event_type="suspicious_request",
        ip_address="192.168.1.100",
        action_taken="logged",
        reason="Test with request",
        request=mock_request,
    )

    mock_agent.send_event.assert_called_once()
    sent_event = mock_agent.send_event.call_args[0][0]

    assert sent_event.endpoint == "/api/v1/test"
    assert sent_event.method == "GET"
    assert sent_event.user_agent == "TestBrowser/1.0"

    mock_request.headers.get.assert_called_once_with("User-Agent")


def test_send_agent_event_promotes_decorator_type_and_rule_type() -> None:
    mock_agent = MagicMock()

    send_agent_event(
        agent_handler=mock_agent,
        event_type="suspicious_request",
        ip_address="192.168.1.100",
        action_taken="logged",
        reason="test reason",
        decorator_type="access_control",
        rule_type="ip_whitelist",
    )

    mock_agent.send_event.assert_called_once()
    sent_event = mock_agent.send_event.call_args[0][0]

    assert sent_event.decorator_type == "access_control"
    assert sent_event.rule_type == "ip_whitelist"
    assert sent_event.handler_name == "ip_extraction"
    assert sent_event.metadata == {
        "decorator_type": "access_control",
        "rule_type": "ip_whitelist",
    }
