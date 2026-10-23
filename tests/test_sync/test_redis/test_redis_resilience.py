from unittest.mock import MagicMock, patch

from guard_core.models import SyncSecurityConfig
from guard_core.sync.handlers.redis_handler import redis_handler


def test_connection_kwargs_from_config() -> None:
    config = SyncSecurityConfig(
        redis_url="redis://localhost:6379",
        redis_socket_timeout=0.5,
        redis_socket_connect_timeout=0.25,
        redis_health_check_interval=15,
        redis_max_connections=20,
        redis_retries=2,
    )
    handler = redis_handler(config)

    kwargs = handler._connection_kwargs()

    assert kwargs["socket_timeout"] == 0.5
    assert kwargs["socket_connect_timeout"] == 0.25
    assert kwargs["health_check_interval"] == 15
    assert "max_connections" not in kwargs
    assert "retry" in kwargs
    assert kwargs["retry_on_error"]


def test_connection_kwargs_retries_disabled() -> None:
    config = SyncSecurityConfig(
        redis_url="redis://localhost:6379",
        redis_retries=0,
        redis_max_connections=None,
    )
    handler = redis_handler(config)

    kwargs = handler._connection_kwargs()

    assert "retry" not in kwargs
    assert "retry_on_error" not in kwargs


def test_initialize_passes_connection_kwargs() -> None:
    config = SyncSecurityConfig(
        redis_url="redis://localhost:6379",
        redis_socket_timeout=0.5,
        redis_socket_connect_timeout=0.25,
    )
    handler = redis_handler(config)

    with patch(
        "guard_core.sync.handlers.redis_handler._build_redis_client"
    ) as mock_build:
        mock_build.return_value = MagicMock()
        handler.initialize()

    args, kwargs = mock_build.call_args
    assert args == ("redis://localhost:6379", 100, 1.0)
    assert kwargs["socket_timeout"] == 0.5
    assert kwargs["socket_connect_timeout"] == 0.25
    handler.close()


def test_initialize_passes_the_pool_size_and_timeout() -> None:
    config = SyncSecurityConfig(
        redis_url="redis://localhost:6379",
        redis_max_connections=20,
        redis_pool_timeout=0.4,
    )
    handler = redis_handler(config)

    with patch(
        "guard_core.sync.handlers.redis_handler._build_redis_client"
    ) as mock_build:
        mock_build.return_value = MagicMock()
        handler.initialize()

    args, _ = mock_build.call_args
    assert args == ("redis://localhost:6379", 20, 0.4)
    handler.close()


def test_the_client_is_built_on_the_fast_path_pool() -> None:
    from guard_core.sync.handlers._redis_fast_pool import FastPathConnectionPool
    from guard_core.sync.handlers.redis_handler import _build_redis_client

    client = _build_redis_client(
        "redis://localhost:6379", 7, 0.5, socket_timeout=0.5, health_check_interval=0
    )
    pool = client.connection_pool
    try:
        assert isinstance(pool, FastPathConnectionPool)
        assert pool.max_connections == 7
        assert pool._wait_timeout == 0.5
        assert pool.connection_kwargs["decode_responses"] is True
        assert pool.connection_kwargs["socket_timeout"] == 0.5
        assert client.auto_close_connection_pool is True
    finally:
        client.close()
