import logging
from collections.abc import AsyncGenerator
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from guard_core.core.initialization.handler_initializer import HandlerInitializer
from guard_core.handlers.security_headers_handler import (
    SecurityHeadersManager,
    security_headers_manager,
)
from guard_core.models import SecurityConfig
from guard_core.protocols.agent_protocol import DynamicRulesProtocol


@pytest.fixture
async def headers_manager() -> AsyncGenerator[SecurityHeadersManager, None]:
    await security_headers_manager.reset()
    yield security_headers_manager
    await security_headers_manager.reset()


@pytest.mark.asyncio
async def test_initialize_agent(headers_manager: SecurityHeadersManager) -> None:
    mock_agent = AsyncMock()

    await headers_manager.initialize_agent(mock_agent)

    assert headers_manager.agent_handler == mock_agent


@pytest.mark.asyncio
async def test_send_headers_applied_event_no_agent(
    headers_manager: SecurityHeadersManager,
) -> None:
    headers_manager.agent_handler = None

    await headers_manager._send_headers_applied_event(
        "/api/test", {"X-Content-Type-Options": "nosniff"}
    )


@pytest.mark.asyncio
async def test_send_headers_applied_event_with_mock_agent(
    headers_manager: SecurityHeadersManager,
) -> None:
    mock_agent = MagicMock()
    mock_agent.send_event = AsyncMock()

    headers_manager.agent_handler = mock_agent

    headers = {
        "X-Content-Type-Options": "nosniff",
        "Content-Security-Policy": "default-src 'self'",
        "Strict-Transport-Security": "max-age=31536000",
    }

    await headers_manager._send_headers_applied_event("/api/test", headers)

    assert headers_manager.agent_handler == mock_agent


@pytest.mark.asyncio
async def test_send_headers_event_with_actual_exception(
    headers_manager: SecurityHeadersManager,
) -> None:
    mock_agent = MagicMock()
    mock_agent.send_event = AsyncMock(side_effect=Exception("Network error"))

    headers_manager.agent_handler = mock_agent

    import sys

    mock_guard_agent = MagicMock()
    # a stand-in model class: get_telemetry_model only hands out classes
    mock_event_class = MagicMock(spec=type)
    mock_event_instance = MagicMock()
    mock_event_class.return_value = mock_event_instance
    mock_guard_agent.SecurityEvent = mock_event_class

    sys.modules["guard_agent"] = mock_guard_agent

    try:
        await headers_manager._send_headers_applied_event(
            "/api/test", {"X-Content-Type-Options": "nosniff"}
        )

        mock_event_class.assert_called_once()

        mock_agent.send_event.assert_called_once_with(mock_event_instance)
    finally:
        if "guard_agent" in sys.modules:
            del sys.modules["guard_agent"]


@pytest.mark.asyncio
async def test_send_csp_violation_event_no_agent(
    headers_manager: SecurityHeadersManager,
) -> None:
    headers_manager.agent_handler = None

    csp_report: dict[str, Any] = {
        "document-uri": "https://example.com/page",
        "violated-directive": "script-src",
        "blocked-uri": "https://evil.com/script.js",
    }

    await headers_manager._send_csp_violation_event(csp_report)


@pytest.mark.asyncio
async def test_send_csp_violation_event_with_mock_agent(
    headers_manager: SecurityHeadersManager,
) -> None:
    mock_agent = MagicMock()
    mock_agent.send_event = AsyncMock()

    headers_manager.agent_handler = mock_agent

    csp_report: dict[str, Any] = {
        "document-uri": "https://example.com/page",
        "violated-directive": "script-src",
        "blocked-uri": "https://evil.com/script.js",
        "source-file": "https://example.com/app.js",
        "line-number": 42,
    }

    await headers_manager._send_csp_violation_event(csp_report)

    assert headers_manager.agent_handler == mock_agent


@pytest.mark.asyncio
async def test_send_csp_violation_event_redacts_source_file(
    headers_manager: SecurityHeadersManager,
) -> None:
    mock_agent = MagicMock()
    mock_agent.send_event = AsyncMock()
    headers_manager.agent_handler = mock_agent

    csp_report: dict[str, Any] = {
        "document-uri": "https://example.com/page",
        "violated-directive": "script-src",
        "blocked-uri": "https://evil.com/script.js",
        "source-file": "https://cdn.example/app.js?api_key=SECRET-source-file-test",
        "line-number": 42,
    }

    await headers_manager._send_csp_violation_event(csp_report)

    event = mock_agent.send_event.call_args[0][0]
    assert "SECRET-source-file-test" not in event.metadata["source_file"]
    assert event.metadata["line_number"] == 42


@pytest.mark.asyncio
async def test_send_csp_violation_event_coerces_string_line_number_to_int(
    headers_manager: SecurityHeadersManager,
) -> None:
    mock_agent = MagicMock()
    mock_agent.send_event = AsyncMock()
    headers_manager.agent_handler = mock_agent

    csp_report: dict[str, Any] = {
        "document-uri": "https://example.com/page",
        "violated-directive": "script-src",
        "blocked-uri": "https://evil.com/script.js",
        "line-number": "17",
    }

    await headers_manager._send_csp_violation_event(csp_report)

    event = mock_agent.send_event.call_args[0][0]
    assert event.metadata["line_number"] == 17


@pytest.mark.asyncio
async def test_send_csp_violation_event_drops_non_numeric_line_number(
    headers_manager: SecurityHeadersManager,
) -> None:
    mock_agent = MagicMock()
    mock_agent.send_event = AsyncMock()
    headers_manager.agent_handler = mock_agent

    csp_report: dict[str, Any] = {
        "document-uri": "https://example.com/page",
        "violated-directive": "script-src",
        "blocked-uri": "https://evil.com/script.js",
        "line-number": "not-a-number",
    }

    await headers_manager._send_csp_violation_event(csp_report)

    event = mock_agent.send_event.call_args[0][0]
    assert event.metadata["line_number"] is None


@pytest.mark.asyncio
async def test_send_csp_violation_event_exception_text_redacted(
    headers_manager: SecurityHeadersManager,
    caplog: pytest.LogCaptureFixture,
) -> None:
    mock_agent = MagicMock()
    secret = "password=hunter2topsecretvalue"
    mock_agent.send_event = AsyncMock(side_effect=Exception(f"send failed: {secret}"))
    headers_manager.agent_handler = mock_agent

    csp_report: dict[str, Any] = {
        "document-uri": "https://example.com/page",
        "violated-directive": "script-src",
        "blocked-uri": "https://evil.com/script.js",
    }

    with caplog.at_level(logging.DEBUG, logger="guard_core.handlers.security_headers"):
        await headers_manager._send_csp_violation_event(csp_report)

    assert "hunter2" not in caplog.text
    assert "[REDACTED]" in caplog.text


@pytest.mark.asyncio
async def test_send_csp_violation_event_with_actual_exception(
    headers_manager: SecurityHeadersManager,
) -> None:
    mock_agent = MagicMock()
    mock_agent.send_event = AsyncMock(side_effect=Exception("API error"))

    headers_manager.agent_handler = mock_agent

    csp_report: dict[str, Any] = {
        "document-uri": "https://example.com",
        "violated-directive": "script-src",
        "blocked-uri": "https://evil.com/script.js",
    }

    import sys

    mock_guard_agent = MagicMock()
    # a stand-in model class: get_telemetry_model only hands out classes
    mock_event_class = MagicMock(spec=type)
    mock_event_instance = MagicMock()
    mock_event_class.return_value = mock_event_instance
    mock_guard_agent.SecurityEvent = mock_event_class

    sys.modules["guard_agent"] = mock_guard_agent

    try:
        await headers_manager._send_csp_violation_event(csp_report)

        mock_event_class.assert_called_once()

        mock_agent.send_event.assert_called_once_with(mock_event_instance)
    finally:
        if "guard_agent" in sys.modules:
            del sys.modules["guard_agent"]


@pytest.mark.asyncio
async def test_validate_csp_report_with_agent(
    headers_manager: SecurityHeadersManager,
) -> None:
    mock_agent = MagicMock()
    mock_agent.send_event = AsyncMock()

    headers_manager.agent_handler = mock_agent

    valid_report = {
        "csp-report": {
            "document-uri": "https://example.com",
            "violated-directive": "script-src",
            "blocked-uri": "https://evil.com/script.js",
        }
    }

    result = await headers_manager.validate_csp_report(valid_report)

    assert result is True
    assert headers_manager.agent_handler == mock_agent


@pytest.mark.asyncio
async def test_get_headers_with_agent(
    headers_manager: SecurityHeadersManager,
) -> None:
    mock_agent = MagicMock()
    mock_agent.send_event = AsyncMock()

    headers_manager.agent_handler = mock_agent
    headers_manager.enabled = True

    headers = await headers_manager.get_headers("/api/secure")

    assert "X-Content-Type-Options" in headers
    assert "X-Frame-Options" in headers

    assert headers_manager.agent_handler == mock_agent


@pytest.mark.asyncio
async def test_get_headers_no_agent_no_path(
    headers_manager: SecurityHeadersManager,
) -> None:
    headers_manager.agent_handler = None
    headers_manager.enabled = True

    headers = await headers_manager.get_headers()

    assert "X-Content-Type-Options" in headers
    assert "X-Frame-Options" in headers

    assert "default" in headers_manager.headers_cache


@pytest.mark.asyncio
async def test_get_headers_disabled(
    headers_manager: SecurityHeadersManager,
) -> None:
    headers_manager.enabled = False

    headers = await headers_manager.get_headers("/test")

    assert headers == {}


@pytest.mark.asyncio
async def test_concurrent_access_thread_safety() -> None:
    manager = SecurityHeadersManager()

    async def configure_and_get_headers(config_id: int) -> dict[str, str]:
        manager.configure(custom_headers={f"X-Thread-{config_id}": str(config_id)})
        headers = await manager.get_headers(f"/path/{config_id}")
        return headers

    results = [await configure_and_get_headers(i) for i in range(10)]

    assert len(results) == 10
    for result in results:
        assert isinstance(result, dict)
        assert "X-Content-Type-Options" in result


class _RecordingTransport:
    def __init__(self) -> None:
        self.events: list[Any] = []

    async def start(self) -> None:
        return None

    async def send_event(self, event: object) -> None:
        self.events.append(event)

    async def stop(self) -> None:
        return None

    async def send_metric(self, _: object) -> None:
        return None

    async def initialize_redis(self, _: object) -> None:
        return None

    async def flush_buffer(self) -> None:
        return None

    async def get_dynamic_rules(self) -> DynamicRulesProtocol | None:
        return None

    async def health_check(self) -> bool:
        return True

    def get_stats(self) -> dict[str, Any]:
        return {}


@pytest.mark.asyncio
async def test_csp_violation_reaches_transport_once_wired_through_handler_initializer(
    headers_manager: SecurityHeadersManager,
) -> None:
    transport = _RecordingTransport()
    config = SecurityConfig()
    initializer = HandlerInitializer(config=config, agent_handler=transport)

    await initializer.initialize_agent_integrations()

    assert headers_manager.agent_handler is not None

    csp_report: dict[str, Any] = {
        "csp-report": {
            "document-uri": "https://example.com/page",
            "violated-directive": "script-src",
            "blocked-uri": "https://evil.com/script.js",
        }
    }

    result = await headers_manager.validate_csp_report(csp_report)

    assert result is True
    assert len(transport.events) == 1
    assert transport.events[0].event_type == "csp_violation"
    assert transport.events[0].handler_name == "security_headers"

    await initializer.shutdown_agent_integrations()
    headers_manager.agent_handler = None


@pytest.mark.asyncio
async def test_headers_applied_event_sets_handler_name(
    headers_manager: SecurityHeadersManager,
) -> None:
    transport = _RecordingTransport()
    config = SecurityConfig()
    initializer = HandlerInitializer(config=config, agent_handler=transport)

    await initializer.initialize_agent_integrations()

    assert headers_manager.agent_handler is not None

    await headers_manager.get_headers("/handler-name-path")

    assert len(transport.events) == 1
    assert transport.events[0].event_type == "security_headers_applied"
    assert transport.events[0].handler_name == "security_headers"

    await initializer.shutdown_agent_integrations()
    headers_manager.agent_handler = None


@pytest.mark.asyncio
async def test_muted_event_types_silences_security_headers_applied(
    headers_manager: SecurityHeadersManager,
) -> None:
    transport = _RecordingTransport()
    config = SecurityConfig(muted_event_types={"security_headers_applied"})
    initializer = HandlerInitializer(config=config, agent_handler=transport)

    await initializer.initialize_agent_integrations()

    assert headers_manager.agent_handler is not None

    await headers_manager.get_headers("/muted/path")

    assert transport.events == []

    await initializer.shutdown_agent_integrations()
    headers_manager.agent_handler = None
