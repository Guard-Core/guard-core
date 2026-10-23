import logging
from collections.abc import Generator
from unittest.mock import AsyncMock

import pytest

from guard_core.handlers.suspatterns_handler import SusPatternsManager


def _live_suspatterns_instance() -> SusPatternsManager | None:
    return SusPatternsManager._instance


@pytest.fixture
def cleanup_suspatterns_singleton() -> Generator[None, None, None]:
    original_instance = SusPatternsManager._instance

    SusPatternsManager._instance = None

    yield

    live_instance = _live_suspatterns_instance()
    if live_instance is not None:
        live_instance.custom_patterns.clear()
        live_instance.compiled_custom_patterns.clear()

        original_len = len(SusPatternsManager.patterns)
        while len(live_instance.patterns) > original_len:
            live_instance.patterns.pop()
            live_instance.compiled_patterns.pop()

    SusPatternsManager._instance = original_instance


@pytest.mark.asyncio
async def test_initialize_agent(cleanup_suspatterns_singleton: None) -> None:
    SusPatternsManager._instance = None

    manager = SusPatternsManager()
    mock_agent = AsyncMock()

    await manager.initialize_agent(mock_agent)

    assert manager.agent_handler is mock_agent


@pytest.mark.asyncio
async def test_send_pattern_event_exception_handling(
    cleanup_suspatterns_singleton: None, caplog: pytest.LogCaptureFixture
) -> None:
    SusPatternsManager._instance = None

    manager = SusPatternsManager()
    mock_agent = AsyncMock()
    mock_agent.send_event.side_effect = Exception("Network error")
    manager.agent_handler = mock_agent

    caplog.set_level(logging.ERROR, logger="fastapi_guard.handlers.suspatterns")

    await manager._send_pattern_event(
        event_type="pattern_detected",
        ip_address="192.168.1.100",
        action_taken="blocked",
        reason="Suspicious pattern detected",
        extra_data="test",
    )

    assert "Failed to send pattern event to agent: Network error" in caplog.text


@pytest.mark.asyncio
async def test_detect_pattern_match_no_match(
    cleanup_suspatterns_singleton: None,
) -> None:
    SusPatternsManager._instance = None

    manager = SusPatternsManager()
    mock_agent = AsyncMock()
    manager.agent_handler = mock_agent

    content = "This is completely safe content with no suspicious patterns"
    ip_address = "192.168.1.100"

    result, matched_pattern = await manager.detect_pattern_match(
        content, ip_address, "test_context"
    )

    assert result is False
    assert matched_pattern is None
    mock_agent.send_event.assert_not_called()


@pytest.mark.asyncio
async def test_add_pattern_with_agent_event(
    cleanup_suspatterns_singleton: None,
) -> None:
    SusPatternsManager._instance = None

    manager = SusPatternsManager()
    mock_agent = AsyncMock()
    manager.agent_handler = mock_agent

    pattern = r"malicious\d+"
    await manager.add_pattern(pattern, custom=True)

    assert pattern in manager.custom_patterns

    mock_agent.send_event.assert_called_once()
    sent_event = mock_agent.send_event.call_args[0][0]

    assert sent_event.event_type == "pattern_added"
    assert sent_event.ip_address == "system"
    assert sent_event.action_taken == "pattern_added"
    assert sent_event.reason == "Custom pattern added to detection system"
    assert sent_event.handler_name == "sus_patterns"
    assert sent_event.pattern_matched is None
    assert sent_event.metadata["pattern"] == pattern
    assert sent_event.metadata["pattern_type"] == "custom"
    assert sent_event.metadata["total_patterns"] == 1


@pytest.mark.asyncio
async def test_remove_pattern_with_agent_event(
    cleanup_suspatterns_singleton: None,
) -> None:
    SusPatternsManager._instance = None

    manager = SusPatternsManager()
    mock_agent = AsyncMock()
    manager.agent_handler = mock_agent

    manager.custom_patterns.clear()
    manager.compiled_custom_patterns.clear()

    pattern = r"test_pattern\d+"
    await manager.add_pattern(pattern, custom=True)

    mock_agent.reset_mock()

    result = await manager.remove_pattern(pattern, custom=True)

    assert result is True
    assert pattern not in manager.custom_patterns

    mock_agent.send_event.assert_called_once()
    sent_event = mock_agent.send_event.call_args[0][0]

    assert sent_event.event_type == "pattern_removed"
    assert sent_event.ip_address == "system"
    assert sent_event.action_taken == "pattern_removed"
    assert sent_event.reason == "Custom pattern removed from detection system"
    assert sent_event.handler_name == "sus_patterns"
    assert sent_event.pattern_matched is None
    assert sent_event.metadata["pattern"] == pattern
    assert sent_event.metadata["pattern_type"] == "custom"
    assert sent_event.metadata["total_patterns"] == 0
