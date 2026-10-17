from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from guard_agent import SecurityEvent

from guard_core.decorators.base import BaseSecurityDecorator
from guard_core.models import SecurityConfig
from tests.conftest import MockGuardRequest


@pytest.mark.asyncio
async def test_initialize_agent(config: SecurityConfig) -> None:
    decorator = BaseSecurityDecorator(config)

    mock_agent = AsyncMock()
    with patch.object(
        decorator.behavior_tracker, "initialize_agent", AsyncMock()
    ) as mock_init:
        await decorator.initialize_agent(mock_agent)

        assert decorator.agent_handler is mock_agent
        mock_init.assert_called_once_with(mock_agent)


@pytest.mark.asyncio
async def test_initialize_agent_with_real_behavior_tracker(
    config: SecurityConfig,
) -> None:
    decorator = BaseSecurityDecorator(config)

    mock_agent = AsyncMock()
    await decorator.initialize_agent(mock_agent)

    assert decorator.agent_handler is mock_agent
    assert decorator.behavior_tracker.agent_handler is mock_agent


@pytest.mark.parametrize(
    "event_type,action,reason,decorator_type,metadata,user_agent,expected_ip,test_scenario",
    [
        (
            "rate_limited",
            "blocked",
            "Rate limit exceeded",
            "rate_limit",
            {"requests_made": 101},
            "test",
            "10.0.0.1",
            "basic_success",
        ),
        (
            "decorator_violation",
            "allowed",
            "test passed",
            "custom_decorator",
            {},
            None,
            "172.16.0.1",
            "no_user_agent",
        ),
        (
            "content_filtered",
            "quarantined",
            "Suspicious file detected",
            "file_scanner",
            {
                "file_size": 1048576,
                "file_type": "application/pdf",
                "scan_results": {"malware": False, "suspicious": True},
                "tags": ["upload", "suspicious", "large-file"],
            },
            "test-agent",
            "203.0.113.0",
            "complex_metadata",
        ),
    ],
)
@pytest.mark.asyncio
async def test_send_decorator_event_scenarios(
    config: SecurityConfig,
    mock_guard_agent: Any,
    event_type: str,
    action: str,
    reason: str,
    decorator_type: str,
    metadata: dict[str, Any],
    user_agent: str | None,
    expected_ip: str,
    test_scenario: str,
) -> None:
    decorator = BaseSecurityDecorator(config)
    decorator.agent_handler = AsyncMock()

    headers = {"User-Agent": user_agent} if user_agent else {}
    request = MockGuardRequest(
        path="/api/test",
        method="POST",
        headers=headers,
    )

    with patch(
        "guard_core.core.events.middleware_events.extract_client_ip",
        AsyncMock(return_value=expected_ip),
    ):
        await decorator.send_decorator_event(
            event_type, request, action, reason, decorator_type, **metadata
        )

        decorator.agent_handler.send_event.assert_called_once()

        sent_event = decorator.agent_handler.send_event.call_args[0][0]

        assert isinstance(sent_event, SecurityEvent)
        assert sent_event.event_type == event_type
        assert sent_event.ip_address == expected_ip
        assert sent_event.decorator_type == decorator_type
        assert sent_event.metadata == {**metadata, "decorator_type": decorator_type}
        assert sent_event.action_taken == action
        assert sent_event.reason == reason
        assert sent_event.endpoint == "/api/test"
        assert sent_event.method == "POST"
        assert sent_event.user_agent == user_agent


@pytest.mark.parametrize(
    "helper_method,expected_event_type,expected_action,args,kwargs,expected_reason",
    [
        (
            "send_access_denied_event",
            "access_denied",
            "blocked",
            ("IP not whitelisted", "ip_whitelist"),
            {"allowed_ips": ["10.0.0.0/8"]},
            "IP not whitelisted",
        ),
        (
            "send_authentication_failed_event",
            "authentication_failed",
            "blocked",
            ("Invalid credentials", "basic"),
            {"username": "testuser"},
            "Invalid credentials",
        ),
        (
            "send_rate_limit_event",
            "rate_limited",
            "blocked",
            (100, 60),
            {"requests_made": 101, "ip_address": "192.168.1.100"},
            "Rate limit exceeded: 100 requests per 60s",
        ),
        (
            "send_decorator_violation_event",
            "decorator_violation",
            "blocked",
            ("access_control", "Unauthorized access attempt"),
            {"user_id": "12345", "endpoint": "/api/protected"},
            "Unauthorized access attempt",
        ),
    ],
)
@pytest.mark.asyncio
async def test_helper_methods(
    config: SecurityConfig,
    helper_method: str,
    expected_event_type: str,
    expected_action: str,
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    expected_reason: str,
) -> None:
    decorator = BaseSecurityDecorator(config)
    decorator.agent_handler = AsyncMock()

    request = MockGuardRequest(
        path="/api/test",
        method="GET",
        headers={"User-Agent": "test-agent"},
    )

    with patch.object(decorator, "send_decorator_event", AsyncMock()) as mock_send:
        method = getattr(decorator, helper_method)
        await method(request, *args, **kwargs)

        expected_decorator_type = (
            "authentication"
            if helper_method == "send_authentication_failed_event"
            else "rate_limiting"
            if helper_method == "send_rate_limit_event"
            else args[0]
            if helper_method == "send_decorator_violation_event"
            else args[1]
        )

        expected_kwargs = {
            "event_type": expected_event_type,
            "request": request,
            "action_taken": expected_action,
            "reason": expected_reason,
            "decorator_type": expected_decorator_type,
            **kwargs,
        }

        if helper_method == "send_authentication_failed_event":
            expected_kwargs["auth_type"] = args[1]
        elif helper_method == "send_rate_limit_event":
            expected_kwargs["limit"] = args[0]
            expected_kwargs["window"] = args[1]

        mock_send.assert_called_once_with(**expected_kwargs)


@pytest.mark.parametrize(
    "error_scenario,side_effect,expected_log_message",
    [
        (
            "agent_exception",
            Exception("Network error"),
            "Failed to send security event to agent",
        ),
        (
            "ip_extraction_failure",
            "ip_extraction_error",
            "Failed to send security event to agent",
        ),
    ],
)
@pytest.mark.asyncio
async def test_error_conditions(
    config: SecurityConfig,
    caplog: pytest.LogCaptureFixture,
    error_scenario: str,
    side_effect: Any,
    expected_log_message: str,
) -> None:
    decorator = BaseSecurityDecorator(config)
    decorator.agent_handler = AsyncMock()

    request = MockGuardRequest(
        path="/api/test",
        method="GET",
        headers={"User-Agent": "test-agent"},
    )

    if error_scenario == "agent_exception":
        decorator.agent_handler.send_event.side_effect = side_effect
        with patch(
            "guard_core.core.events.middleware_events.extract_client_ip",
            AsyncMock(return_value="192.168.1.1"),
        ):
            await decorator.send_decorator_event(
                "config_violation", request, "action", "reason", "test_decorator"
            )
    else:
        with patch(
            "guard_core.core.events.middleware_events.extract_client_ip",
            AsyncMock(side_effect=Exception("IP extraction failed")),
        ):
            await decorator.send_decorator_event(
                "config_violation", request, "action", "reason", "test_decorator"
            )

    assert expected_log_message in caplog.text


@pytest.mark.asyncio
async def test_send_decorator_event_no_agent(config: SecurityConfig) -> None:
    decorator = BaseSecurityDecorator(config)
    decorator.agent_handler = None

    request = MockGuardRequest()

    await decorator.send_decorator_event(
        "config_violation", request, "action", "reason", "decorator_type"
    )


@pytest.mark.asyncio
async def test_multiple_event_sends(
    config: SecurityConfig, mock_guard_agent: Any
) -> None:
    decorator = BaseSecurityDecorator(config)
    decorator.agent_handler = AsyncMock()

    request = MockGuardRequest(
        path="/api/test",
        method="GET",
        headers={"User-Agent": "test-agent"},
    )

    with patch(
        "guard_core.core.events.middleware_events.extract_client_ip",
        AsyncMock(return_value="192.168.1.1"),
    ):
        await decorator.send_decorator_event(
            "decorator_violation", request, "action1", "reason1", "decorator1"
        )
        await decorator.send_decorator_event(
            "access_denied", request, "action2", "reason2", "decorator2"
        )
        await decorator.send_decorator_event(
            "authentication_failed", request, "action3", "reason3", "decorator3"
        )

        assert decorator.agent_handler.send_event.call_count == 3


def test_decorator_initialization(config: SecurityConfig) -> None:
    config = SecurityConfig(enable_penetration_detection=True)
    decorator = BaseSecurityDecorator(config)

    assert decorator.config is config
    assert decorator._route_configs == {}
    assert decorator.behavior_tracker is not None
    assert decorator.agent_handler is None


def test_get_route_config(config: SecurityConfig) -> None:
    decorator = BaseSecurityDecorator(config)

    def test_func() -> None:
        pass  # pragma: no cover

    route_config = decorator._ensure_route_config(test_func)
    route_id = decorator._get_route_id(test_func)

    retrieved_config = decorator.get_route_config(route_id)
    assert retrieved_config is route_config

    assert decorator.get_route_config("non_existent") is None


def test_route_id_generation(config: SecurityConfig) -> None:
    decorator = BaseSecurityDecorator(config)

    def test_function() -> None:
        pass  # pragma: no cover

    route_id = decorator._get_route_id(test_function)
    assert route_id == f"{test_function.__module__}.{test_function.__qualname__}"


@pytest.mark.parametrize(
    "enable_penetration_detection,expected_suspicious_detection",
    [
        (True, True),
        (False, False),
    ],
)
def test_ensure_route_config(
    config: SecurityConfig,
    enable_penetration_detection: bool,
    expected_suspicious_detection: bool,
) -> None:
    config.enable_penetration_detection = enable_penetration_detection
    decorator = BaseSecurityDecorator(config)

    def test_func() -> None:
        pass  # pragma: no cover

    route_config = decorator._ensure_route_config(test_func)
    assert route_config.enable_suspicious_detection is expected_suspicious_detection


def test_apply_route_config(config: SecurityConfig) -> None:
    decorator = BaseSecurityDecorator(config)

    def test_func() -> None:
        pass  # pragma: no cover

    decorated_func = decorator._apply_route_config(test_func)
    route_id = decorator._get_route_id(test_func)

    assert hasattr(decorated_func, "_guard_route_id")
    assert decorated_func._guard_route_id == route_id


@pytest.mark.parametrize(
    "redis_handler,should_initialize",
    [
        (AsyncMock(), True),
        (None, False),
    ],
)
@pytest.mark.asyncio
async def test_initialize_behavior_tracking(
    config: SecurityConfig,
    redis_handler: AsyncMock | None,
    should_initialize: bool,
) -> None:
    decorator = BaseSecurityDecorator(config)

    if should_initialize:
        with patch.object(
            decorator.behavior_tracker, "initialize_redis", AsyncMock()
        ) as mock_init:
            await decorator.initialize_behavior_tracking(redis_handler)
            mock_init.assert_called_once_with(redis_handler)
    else:
        await decorator.initialize_behavior_tracking(redis_handler)
