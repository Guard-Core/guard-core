import logging
import threading
from collections.abc import Generator
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from guard_core.models import SecurityConfig
from guard_core.sync.handlers.ratelimit_handler import RateLimitManager, RateLimitTier
from tests.test_sync.conftest import SyncMockGuardRequest


class _FakeErrorResponse:
    def __init__(self, status_code: int, message: str) -> None:
        self.status_code = status_code
        self.message = message
        self.headers: dict[str, str] = {}


@pytest.fixture(autouse=True)
def bounded_ratelimit_windows() -> Generator[Any, Any, Any]:
    def custom_new(
        cls: type[RateLimitManager], config: SecurityConfig
    ) -> RateLimitManager:
        instance = object.__new__(cls)
        instance.config = config
        instance.request_timestamps = __import__("collections").defaultdict(
            lambda: __import__("collections").deque(maxlen=config.rate_limit * 2)
        )
        instance.logger = logging.getLogger(__name__)
        instance.redis_handler = None
        instance.agent_handler = None
        instance.rate_limit_script_sha = None
        instance._lock = threading.Lock()
        return instance

    with (
        patch.object(RateLimitManager, "__new__", custom_new),
        patch(
            "guard_core.sync.handlers.ratelimit_handler.SecurityEvent", create=True
        ) as mock_event,
    ):
        from guard_agent.models import SecurityEvent

        mock_event.side_effect = SecurityEvent
        yield


def test_initialize_agent() -> None:
    config = SecurityConfig()
    manager = RateLimitManager(config)
    mock_agent = MagicMock()

    manager.initialize_agent(mock_agent)

    assert manager.agent_handler is mock_agent


def test_send_rate_limit_event_success() -> None:
    config = SecurityConfig(
        enable_rate_limiting=True, rate_limit=100, rate_limit_window=60
    )
    manager = RateLimitManager(config)
    mock_agent = MagicMock()
    manager.agent_handler = mock_agent

    mock_request = SyncMockGuardRequest(path="/api/test", method="GET")

    manager._send_rate_limit_event(
        request=mock_request, client_ip="192.168.1.100", request_count=150
    )

    mock_agent.send_event.assert_called_once()
    sent_event = mock_agent.send_event.call_args[0][0]

    assert sent_event.event_type == "rate_limited"
    assert sent_event.ip_address == "192.168.1.100"
    assert sent_event.action_taken == "request_blocked"
    assert sent_event.reason == "Rate limit exceeded: 150 requests in 60s window"
    assert sent_event.endpoint == "/api/test"
    assert sent_event.method == "GET"
    assert sent_event.metadata["request_count"] == 150
    assert sent_event.metadata["rate_limit"] == 100
    assert sent_event.metadata["window"] == 60


def test_send_rate_limit_event_exception_handling(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SecurityConfig(
        enable_rate_limiting=True, rate_limit=100, rate_limit_window=60
    )
    manager = RateLimitManager(config)
    mock_agent = MagicMock()
    mock_agent.send_event.side_effect = Exception("Network error")
    manager.agent_handler = mock_agent

    mock_request = SyncMockGuardRequest(path="/api/data", method="POST")

    caplog.set_level(logging.ERROR)

    manager._send_rate_limit_event(
        request=mock_request, client_ip="192.168.1.101", request_count=200
    )

    assert "Failed to send rate limit event to agent: Network error" in caplog.text


def test_check_rate_limit_agent_event_called() -> None:
    config = SecurityConfig(
        enable_rate_limiting=True,
        enable_redis=False,
        rate_limit=1,
        rate_limit_window=60,
        log_suspicious_level="WARNING",
    )
    manager = RateLimitManager(config)

    mock_agent = MagicMock()
    manager.agent_handler = mock_agent

    mock_request = SyncMockGuardRequest(path="/api/endpoint", method="GET")

    def mock_error_response(status_code: int, message: str) -> Any:
        return _FakeErrorResponse(status_code, message)

    with (
        patch("guard_core.sync.handlers.ratelimit_handler.log_activity"),
        patch.object(manager, "_send_rate_limit_event") as mock_send_event,
    ):
        result1 = manager.check_rate_limit(
            request=mock_request,
            client_ip="192.168.1.100",
            create_error_response=mock_error_response,
        )
        assert result1 is None

        result2: Any = manager.check_rate_limit(
            request=mock_request,
            client_ip="192.168.1.100",
            create_error_response=mock_error_response,
        )

        assert result2.status_code == 429
        assert result2.message == "Too many requests"
        assert result2.headers["Retry-After"] == "60"

        mock_send_event.assert_called_once_with(
            mock_request,
            "192.168.1.100",
            2,
            config=config,
            tier=RateLimitTier("global", 1, 60),
        )


def test_check_rate_limit_redis_path_with_agent() -> None:
    config = SecurityConfig(
        enable_rate_limiting=True,
        enable_redis=True,
        rate_limit=10,
        rate_limit_window=60,
        log_suspicious_level="WARNING",
    )
    manager = RateLimitManager(config)

    mock_agent = MagicMock()
    manager.agent_handler = mock_agent

    class MockRedisConnection:
        def __init__(self) -> None:
            self.evalsha = MagicMock(return_value=[1, 14, 60])

        def __enter__(self) -> Any:
            return self

        def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> Any:
            return None

    mock_redis = MagicMock()
    mock_redis.get_connection = MagicMock(return_value=MockRedisConnection())
    manager.redis_handler = mock_redis
    manager.rate_limit_script_sha = "test_sha"

    mock_request = SyncMockGuardRequest(path="/api/test", method="POST")

    def mock_error_response(status_code: int, message: str) -> Any:
        return _FakeErrorResponse(status_code, message)

    with patch("guard_core.sync.handlers.ratelimit_handler.log_activity"):
        result: Any = manager.check_rate_limit(
            request=mock_request,
            client_ip="192.168.1.200",
            create_error_response=mock_error_response,
        )

        assert result.status_code == 429
        assert result.message == "Too many requests"
        assert result.headers["Retry-After"] == "60"

        mock_agent.send_event.assert_called_once()
        sent_event = mock_agent.send_event.call_args[0][0]

        assert sent_event.event_type == "rate_limited"
        assert sent_event.ip_address == "192.168.1.200"
        assert sent_event.action_taken == "request_blocked"
        assert "Rate limit exceeded" in sent_event.reason
        assert sent_event.endpoint == "/api/test"
        assert sent_event.method == "POST"
        assert sent_event.metadata["request_count"] == 15
        assert sent_event.handler_name == "rate_limit"


def test_send_rate_limit_event_redacts_sensitive_endpoint_matrix_params() -> None:
    config = SecurityConfig(
        enable_rate_limiting=True,
        rate_limit=100,
        rate_limit_window=60,
        log_sensitive_params=frozenset({"token"}),
    )
    manager = RateLimitManager(config)
    mock_agent = MagicMock()
    manager.agent_handler = mock_agent

    mock_request = SyncMockGuardRequest(
        path="/api/data;token=supersecret", method="GET"
    )

    manager._send_rate_limit_event(
        request=mock_request, client_ip="192.168.1.100", request_count=150
    )

    sent_event = mock_agent.send_event.call_args[0][0]
    assert sent_event.endpoint == "/api/data;token=[REDACTED]"


def test_handle_rate_limit_exceeded_uses_the_passed_configs_sensitive_sets() -> None:
    config_a = SecurityConfig(
        enable_rate_limiting=True,
        rate_limit=1,
        rate_limit_window=60,
        log_sensitive_params=frozenset({"token_a"}),
    )
    config_b = SecurityConfig(
        enable_rate_limiting=True,
        rate_limit=1,
        rate_limit_window=60,
        log_sensitive_params=frozenset({"token_b"}),
    )

    manager = RateLimitManager(config_a)
    assert manager.config is config_a

    mock_request = SyncMockGuardRequest(path="/api/endpoint", method="GET")

    def mock_error_response(status_code: int, message: str) -> Any:
        return _FakeErrorResponse(status_code, message)

    with patch(
        "guard_core.sync.handlers.ratelimit_handler.log_activity"
    ) as mock_log_activity:
        manager._handle_rate_limit_exceeded(
            mock_request,
            "192.168.1.50",
            2,
            mock_error_response,
            config=config_b,
        )

    assert mock_log_activity.call_args.kwargs["sensitive_params"] == frozenset(
        {"token_b"}
    )
