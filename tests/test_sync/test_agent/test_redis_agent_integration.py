import logging
from unittest.mock import MagicMock, patch

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.handlers.redis_handler import RedisManager, _redact_redis_url

_REAL_REDIS_MANAGER_INITIALIZE = RedisManager.initialize


@pytest.fixture(autouse=True)
def patch_security_event() -> object:
    with patch(
        "guard_core.sync.handlers.redis_handler.SecurityEvent", create=True
    ) as mock_event:
        from guard_agent.models import SecurityEvent

        mock_event.side_effect = SecurityEvent
        yield


def test_redact_redis_url_returns_none_for_none_url() -> None:
    assert _redact_redis_url(None) is None


def test_redact_redis_url_without_explicit_port() -> None:
    assert _redact_redis_url("redis://:secret@localhost/0") == "redis://localhost/0"


def test_redact_redis_url_malformed_port_does_not_raise() -> None:
    assert _redact_redis_url("redis://host:notanumber/0") == "redis://<unparseable>"


def test_redact_redis_url_out_of_range_port_does_not_raise() -> None:
    assert _redact_redis_url("redis://host:99999/0") == "redis://<unparseable>"


def test_redact_redis_url_unbalanced_ipv6_brackets_does_not_raise() -> None:
    assert _redact_redis_url("redis://[::1:6379/0") == "redis://<unparseable>"


def test_redact_redis_url_ipv6_host_with_password() -> None:
    assert _redact_redis_url("redis://:secret@[::1]:6379/0") == "redis://[::1]:6379/0"


def test_redact_redis_url_unix_socket_left_unchanged() -> None:
    assert _redact_redis_url("unix:///tmp/redis.sock") == "unix:///tmp/redis.sock"


def test_redact_redis_url_unix_socket_drops_credential_params() -> None:
    assert (
        _redact_redis_url("unix:///tmp/redis.sock?password=pw&db=0&username=u")
        == "unix:///tmp/redis.sock?db=0"
    )
    assert _redact_redis_url("unix:///tmp/redis.sock?password=pw") == (
        "unix:///tmp/redis.sock"
    )


def test_redact_redis_url_drops_credential_params_redis_py_decodes() -> None:
    assert (
        _redact_redis_url("unix:///tmp/redis.sock?pass%77ord=pw&db=0")
        == "unix:///tmp/redis.sock?db=0"
    )
    assert (
        _redact_redis_url("redis://h:6379/0?user%6Eame=u&pass%77ord=pw")
        == "redis://h:6379/0"
    )


def test_redact_redis_url_keeps_scheme_host_port_db_query_drops_userinfo() -> None:
    assert (
        _redact_redis_url("rediss://user:pw@host:6380/1?ssl=true")
        == "rediss://host:6380/1?ssl=true"
    )


def test_redact_redis_url_empty_string_does_not_raise() -> None:
    assert _redact_redis_url("") == ""


def test_initialize_agent() -> None:
    config = SyncSecurityConfig(enable_redis=True, redis_url="redis://localhost")
    manager = RedisManager(config)
    mock_agent = MagicMock()

    manager.initialize_agent(mock_agent)

    assert manager.agent_handler is mock_agent


def test_send_redis_event_no_agent() -> None:
    config = SyncSecurityConfig(enable_redis=True, redis_url="redis://localhost")
    manager = RedisManager(config)
    manager.agent_handler = None

    manager._send_redis_event(
        event_type="redis_connection",
        action_taken="test_action",
        reason="test reason",
    )


def test_send_redis_event_success() -> None:
    config = SyncSecurityConfig(enable_redis=True, redis_url="redis://localhost")
    manager = RedisManager(config)
    mock_agent = MagicMock()
    manager.agent_handler = mock_agent

    manager._send_redis_event(
        event_type="redis_connection",
        action_taken="connection_established",
        reason="Redis connection successfully established",
        redis_url="redis://localhost",
        extra_data="test",
    )

    mock_agent.send_event.assert_called_once()
    sent_event = mock_agent.send_event.call_args[0][0]

    assert sent_event.event_type == "redis_connection"
    assert sent_event.ip_address == "system"
    assert sent_event.action_taken == "connection_established"
    assert sent_event.reason == "Redis connection successfully established"
    assert sent_event.metadata["redis_url"] == "redis://localhost"
    assert sent_event.metadata["extra_data"] == "test"


def test_initialize_redacts_redis_url_password_on_connect_event() -> None:
    config = SyncSecurityConfig(
        enable_redis=True, redis_url="redis://:secret-pw@127.0.0.1:6399"
    )
    manager = RedisManager(config)
    mock_agent = MagicMock()
    manager.agent_handler = mock_agent

    fake_redis = MagicMock()
    fake_redis.ping = MagicMock(return_value=True)

    with (
        patch.object(RedisManager, "initialize", _REAL_REDIS_MANAGER_INITIALIZE),
        patch(
            "guard_core.sync.handlers.redis_handler._build_redis_client",
            return_value=fake_redis,
        ),
    ):
        manager.initialize()

    mock_agent.send_event.assert_called_once()
    sent_event = mock_agent.send_event.call_args[0][0]

    assert "secret-pw" not in sent_event.metadata["redis_url"]
    assert sent_event.metadata["redis_url"] == "redis://127.0.0.1:6399"
    assert sent_event.handler_name == "redis"
    manager._redis = None


def test_initialize_redacts_redis_url_password_on_error_event() -> None:
    from guard_core.exceptions import GuardRedisError

    config = SyncSecurityConfig(
        enable_redis=True, redis_url="redis://:secret-pw@127.0.0.1:6399"
    )
    manager = RedisManager(config)
    mock_agent = MagicMock()
    manager.agent_handler = mock_agent

    with (
        patch.object(RedisManager, "initialize", _REAL_REDIS_MANAGER_INITIALIZE),
        patch(
            "guard_core.sync.handlers.redis_handler._build_redis_client",
            side_effect=Exception("Connection refused"),
        ),
        pytest.raises(GuardRedisError),
    ):
        manager.initialize()

    mock_agent.send_event.assert_called_once()
    sent_event = mock_agent.send_event.call_args[0][0]

    assert "secret-pw" not in sent_event.metadata["redis_url"]
    assert sent_event.metadata["redis_url"] == "redis://127.0.0.1:6399"
    assert sent_event.handler_name == "redis"


def test_send_redis_event_exception_handling(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SyncSecurityConfig(enable_redis=True, redis_url="redis://localhost")
    manager = RedisManager(config)
    mock_agent = MagicMock()
    mock_agent.send_event.side_effect = Exception("Network error")
    manager.agent_handler = mock_agent

    caplog.set_level(logging.ERROR, logger="fastapi_guard.handlers.redis")

    manager._send_redis_event(
        event_type="redis_error",
        action_taken="operation_failed",
        reason="Test failure",
    )

    assert "Failed to send Redis event to agent: Network error" in caplog.text


def test_close_with_agent() -> None:
    config = SyncSecurityConfig(enable_redis=True, redis_url="redis://localhost")
    manager = RedisManager(config)
    mock_agent = MagicMock()
    manager.agent_handler = mock_agent

    mock_redis = MagicMock()
    mock_redis.close = MagicMock()
    manager._redis = mock_redis

    manager.close()

    mock_redis.close.assert_called_once()
    assert manager._redis is None


def test_get_connection_closed_error_with_agent() -> None:
    from guard_core.exceptions import GuardRedisError

    config = SyncSecurityConfig(enable_redis=True, redis_url="redis://localhost")
    manager = RedisManager(config)
    mock_agent = MagicMock()
    manager.agent_handler = mock_agent
    manager._closed = True

    with pytest.raises(GuardRedisError) as exc_info:
        with manager.get_connection():
            pass

    assert exc_info.value.status_code == 503
    assert exc_info.value.detail == "Redis connection closed"

    mock_agent.send_event.assert_called_once()
    sent_event = mock_agent.send_event.call_args[0][0]

    assert sent_event.event_type == "redis_error"
    assert sent_event.action_taken == "operation_failed"
    assert sent_event.reason == "Attempted to use closed Redis connection"
    assert sent_event.metadata["error_type"] == "connection_closed"


def test_get_connection_initialization_failure_with_agent() -> None:
    from guard_core.exceptions import GuardRedisError

    config = SyncSecurityConfig(enable_redis=True, redis_url="redis://localhost")
    manager = RedisManager(config)
    mock_agent = MagicMock()
    manager.agent_handler = mock_agent
    manager._redis = None

    with pytest.raises(GuardRedisError) as exc_info:
        with manager.get_connection():
            pass

    assert exc_info.value.status_code == 503
    assert exc_info.value.detail == "Redis connection failed"

    mock_agent.send_event.assert_called_once()
    sent_event = mock_agent.send_event.call_args[0][0]

    assert sent_event.event_type == "redis_error"
    assert sent_event.action_taken == "operation_failed"
    assert sent_event.reason == "Redis connection is None after initialization"
    assert sent_event.metadata["error_type"] == "initialization_failed"


def test_safe_operation_failure_with_agent() -> None:
    from guard_core.exceptions import GuardRedisError

    config = SyncSecurityConfig(enable_redis=True, redis_url="redis://localhost")
    manager = RedisManager(config)
    mock_agent = MagicMock()
    manager.agent_handler = mock_agent

    def failing_func(conn: object) -> None:
        raise Exception("Operation failed")

    failing_func.__name__ = "failing_func"

    with pytest.raises(GuardRedisError) as exc_info:
        manager.safe_operation(failing_func)

    assert exc_info.value.status_code == 503
    assert exc_info.value.detail == "Redis operation failed"


def test_safe_operation_error_inside_context() -> None:
    from guard_core.exceptions import GuardRedisError

    config = SyncSecurityConfig(enable_redis=True, redis_url="redis://localhost")
    manager = RedisManager(config)
    mock_agent = MagicMock()
    manager.agent_handler = mock_agent

    mock_redis = MagicMock()
    manager._redis = mock_redis

    def failing_operation(conn: object) -> None:
        raise ValueError("Operation error inside context")

    failing_operation.__name__ = "failing_operation"

    with pytest.raises(GuardRedisError) as exc_info:
        manager.safe_operation(failing_operation)

    assert exc_info.value.status_code == 503
    assert exc_info.value.detail == "Redis operation failed"

    calls = mock_agent.send_event.call_args_list
    assert len(calls) > 0

    found = False
    for call in calls:
        event = call[0][0]
        if event.action_taken == "safe_operation_failed":
            found = True
            assert event.event_type == "redis_error"
            assert "Operation error inside context" in event.reason
            assert event.metadata["error_type"] == "safe_operation_error"
            assert event.metadata["function_name"] == "failing_operation"
            break

    assert found, "safe_operation_failed event not found"
    manager._redis = None
