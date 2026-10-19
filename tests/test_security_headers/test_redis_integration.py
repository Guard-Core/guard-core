import json
from collections.abc import AsyncGenerator, AsyncIterator
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from guard_core.handlers.security_headers_handler import (
    SecurityHeadersManager,
    security_headers_manager,
)


def _scanning_connection(keys: list[str]) -> MagicMock:
    async def scan_iter(match: str, count: int) -> AsyncIterator[str]:
        pending = list(keys)
        while pending:
            yield pending.pop(0)

    conn = MagicMock()
    conn.scan_iter = MagicMock(side_effect=scan_iter)
    conn.unlink = AsyncMock(return_value=len(keys))
    conn.keys = AsyncMock()
    return conn


@pytest.fixture
async def headers_manager() -> AsyncGenerator[SecurityHeadersManager, None]:
    original_redis = security_headers_manager.redis_handler
    security_headers_manager.redis_handler = None

    await security_headers_manager.reset()

    yield security_headers_manager

    security_headers_manager.redis_handler = None
    await security_headers_manager.reset()

    security_headers_manager.redis_handler = original_redis


@pytest.mark.asyncio
async def test_initialize_redis(headers_manager: SecurityHeadersManager) -> None:
    mock_redis = AsyncMock()
    mock_redis.get_key = AsyncMock(return_value=None)

    await headers_manager.initialize_redis(mock_redis)

    assert headers_manager.redis_handler == mock_redis
    mock_redis.get_key.assert_called()


@pytest.mark.asyncio
async def test_load_cached_config_from_redis(
    headers_manager: SecurityHeadersManager,
) -> None:
    mock_redis = AsyncMock()

    csp_config = {
        "default-src": ["'self'"],
        "script-src": ["'self'", "https://cdn.com"],
    }
    mock_redis.get_key = AsyncMock(
        side_effect=[
            json.dumps(csp_config),
            json.dumps({"max_age": 31536000, "include_subdomains": True}),
            json.dumps({"X-Custom": "value"}),
        ]
    )

    headers_manager.redis_handler = mock_redis
    await headers_manager._load_cached_config()

    assert headers_manager.csp_config == csp_config
    assert headers_manager.hsts_config is not None
    assert headers_manager.hsts_config["max_age"] == 31536000
    assert headers_manager.custom_headers["X-Custom"] == "value"

    assert mock_redis.get_key.call_count == 3
    mock_redis.get_key.assert_any_call("security_headers", "csp_config")
    mock_redis.get_key.assert_any_call("security_headers", "hsts_config")
    mock_redis.get_key.assert_any_call("security_headers", "custom_headers")


@pytest.mark.asyncio
async def test_load_cached_config_rejects_invalid_custom_header_name(
    headers_manager: SecurityHeadersManager,
    caplog: pytest.LogCaptureFixture,
) -> None:
    mock_redis = AsyncMock()
    mock_redis.get_key = AsyncMock(
        side_effect=[
            None,
            None,
            json.dumps({"X-Evil\r\nSet-Cookie: x=1": "1"}),
        ]
    )

    headers_manager.redis_handler = mock_redis
    await headers_manager._load_cached_config()

    assert headers_manager.custom_headers == {}
    assert "Failed to load cached header config" in caplog.text


@pytest.mark.asyncio
async def test_load_cached_config_warning_sanitises_crlf_in_header_name(
    headers_manager: SecurityHeadersManager,
    caplog: pytest.LogCaptureFixture,
) -> None:
    mock_redis = AsyncMock()
    mock_redis.get_key = AsyncMock(
        side_effect=[
            None,
            None,
            json.dumps({"X-Evil\r\nSet-Cookie: x=1": "1"}),
        ]
    )

    headers_manager.redis_handler = mock_redis
    with caplog.at_level("WARNING"):
        await headers_manager._load_cached_config()

    warning_records = [
        record
        for record in caplog.records
        if "Failed to load cached header config" in record.getMessage()
    ]
    assert len(warning_records) == 1
    message = warning_records[0].getMessage()
    assert "\r" not in message
    assert "\n" not in message
    assert "\\r\\n" in message


@pytest.mark.asyncio
async def test_load_cached_config_rejects_invalid_custom_header_value(
    headers_manager: SecurityHeadersManager,
    caplog: pytest.LogCaptureFixture,
) -> None:
    mock_redis = AsyncMock()
    mock_redis.get_key = AsyncMock(
        side_effect=[
            None,
            None,
            json.dumps({"X-Custom": "ok\r\nSet-Cookie: y=2"}),
        ]
    )

    headers_manager.redis_handler = mock_redis
    await headers_manager._load_cached_config()

    assert headers_manager.custom_headers == {}
    assert "Failed to load cached header config" in caplog.text


@pytest.mark.asyncio
async def test_load_cached_config_redis_error(
    headers_manager: SecurityHeadersManager,
) -> None:
    mock_redis = AsyncMock()
    mock_redis.get_key = AsyncMock(side_effect=Exception("Redis connection error"))

    headers_manager.redis_handler = mock_redis

    await headers_manager._load_cached_config()

    assert headers_manager.csp_config is None
    assert headers_manager.hsts_config is None


@pytest.mark.asyncio
async def test_load_cached_config_no_redis_handler(
    headers_manager: SecurityHeadersManager,
) -> None:
    headers_manager.redis_handler = None

    await headers_manager._load_cached_config()

    assert headers_manager.csp_config is None
    assert headers_manager.hsts_config is None


@pytest.mark.asyncio
async def test_cache_configuration_to_redis(
    headers_manager: SecurityHeadersManager,
) -> None:
    mock_redis = AsyncMock()
    mock_redis.set_key = AsyncMock()

    headers_manager.redis_handler = mock_redis
    headers_manager.csp_config = {"default-src": ["'self'"]}
    headers_manager.hsts_config = {"max_age": 31536000}
    headers_manager.custom_headers = {"X-Custom": "value"}

    await headers_manager._cache_configuration()

    assert mock_redis.set_key.call_count == 3
    mock_redis.set_key.assert_any_call(
        "security_headers",
        "csp_config",
        json.dumps({"default-src": ["'self'"]}),
        ttl=86400,
    )
    mock_redis.set_key.assert_any_call(
        "security_headers", "hsts_config", json.dumps({"max_age": 31536000}), ttl=86400
    )
    mock_redis.set_key.assert_any_call(
        "security_headers",
        "custom_headers",
        json.dumps({"X-Custom": "value"}),
        ttl=86400,
    )


@pytest.mark.asyncio
async def test_cache_configuration_redis_error(
    headers_manager: SecurityHeadersManager,
) -> None:
    mock_redis = AsyncMock()
    mock_redis.set_key = AsyncMock(side_effect=Exception("Redis write error"))

    headers_manager.redis_handler = mock_redis
    headers_manager.csp_config = {"default-src": ["'self'"]}

    await headers_manager._cache_configuration()


@pytest.mark.asyncio
async def test_cache_configuration_no_redis(
    headers_manager: SecurityHeadersManager,
) -> None:
    headers_manager.redis_handler = None
    headers_manager.csp_config = {"default-src": ["'self'"]}

    await headers_manager._cache_configuration()


@pytest.mark.asyncio
async def test_cache_configuration_partial_config(
    headers_manager: SecurityHeadersManager,
) -> None:
    mock_redis = AsyncMock()
    mock_redis.set_key = AsyncMock()

    mock_conn = AsyncMock()
    mock_conn.keys = AsyncMock(return_value=[])
    mock_conn.delete = AsyncMock()

    mock_context = AsyncMock()
    mock_context.__aenter__ = AsyncMock(return_value=mock_conn)
    mock_context.__aexit__ = AsyncMock()

    mock_redis.get_connection = AsyncMock(return_value=mock_context)
    mock_redis.config = MagicMock()
    mock_redis.config.redis_prefix = "fastapi_guard:"

    headers_manager.redis_handler = mock_redis
    headers_manager.csp_config = {"default-src": ["'self'"]}
    headers_manager.hsts_config = None
    headers_manager.custom_headers = {}

    await headers_manager._cache_configuration()

    mock_redis.set_key.assert_called_once_with(
        "security_headers",
        "csp_config",
        json.dumps({"default-src": ["'self'"]}),
        ttl=86400,
    )


@pytest.mark.asyncio
async def test_reset_with_redis_proper_async(
    headers_manager: SecurityHeadersManager,
) -> None:
    with patch.object(headers_manager, "redis_handler") as mock_redis:
        mock_conn = _scanning_connection(
            [
                "fastapi_guard:security_headers:csp_config",
                "fastapi_guard:security_headers:custom_headers",
            ]
        )

        mock_context = AsyncMock()
        mock_context.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_context.__aexit__ = AsyncMock()

        mock_redis.get_connection.return_value = mock_context
        mock_redis.config.redis_prefix = "fastapi_guard:"

        headers_manager.custom_headers = {"X-Test": "value"}
        headers_manager.csp_config = {"default-src": ["'self'"]}

        await headers_manager.reset()

        assert len(headers_manager.custom_headers) == 0
        assert headers_manager.csp_config is None


@pytest.mark.asyncio
async def test_reset_with_empty_redis_keys(
    headers_manager: SecurityHeadersManager,
) -> None:
    with patch.object(headers_manager, "redis_handler") as mock_redis:
        mock_conn = _scanning_connection([])

        mock_context = AsyncMock()
        mock_context.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_context.__aexit__ = AsyncMock()

        mock_redis.get_connection.return_value = mock_context
        mock_redis.config.redis_prefix = "fastapi_guard:"

        headers_manager.custom_headers = {"X-Test": "value"}

        await headers_manager.reset()

        assert len(headers_manager.custom_headers) == 0

        mock_conn.scan_iter.assert_called_once_with(
            match="fastapi_guard:security_headers:*", count=500
        )
        mock_conn.keys.assert_not_called()
        mock_conn.unlink.assert_not_called()


@pytest.mark.asyncio
async def test_reset_redis_error(headers_manager: SecurityHeadersManager) -> None:
    mock_context = AsyncMock()
    mock_context.__aenter__ = AsyncMock(side_effect=Exception("Connection failed"))
    mock_context.__aexit__ = AsyncMock()

    mock_redis = MagicMock()
    mock_redis.get_connection.return_value = mock_context
    mock_redis.config.redis_prefix = "fastapi_guard:"

    headers_manager.redis_handler = mock_redis
    headers_manager.custom_headers = {"X-Test": "value"}

    await headers_manager.reset()

    assert len(headers_manager.custom_headers) == 0
    assert headers_manager.enabled


@pytest.mark.asyncio
async def test_reset_without_redis(headers_manager: SecurityHeadersManager) -> None:
    headers_manager.redis_handler = None
    headers_manager.custom_headers = {"X-Test": "value"}
    headers_manager.csp_config = {"default-src": ["'self'"]}

    await headers_manager.reset()

    assert len(headers_manager.custom_headers) == 0
    assert headers_manager.csp_config is None


@pytest.mark.asyncio
async def test_initialize_redis_and_cache_configuration(
    headers_manager: SecurityHeadersManager,
) -> None:
    mock_redis = AsyncMock()
    mock_redis.get_key = AsyncMock(return_value=None)
    mock_redis.set_key = AsyncMock()

    mock_conn = AsyncMock()
    mock_conn.keys = AsyncMock(return_value=[])
    mock_conn.delete = AsyncMock()

    mock_context = AsyncMock()
    mock_context.__aenter__ = AsyncMock(return_value=mock_conn)
    mock_context.__aexit__ = AsyncMock()

    mock_redis.get_connection = AsyncMock(return_value=mock_context)
    mock_redis.config = MagicMock()
    mock_redis.config.redis_prefix = "fastapi_guard:"

    headers_manager.configure(
        csp={"default-src": ["'self'"]},
        hsts_max_age=31536000,
        custom_headers={"X-Custom": "value"},
    )

    await headers_manager.initialize_redis(mock_redis)

    assert headers_manager.redis_handler == mock_redis

    assert mock_redis.get_key.call_count == 3

    assert mock_redis.set_key.call_count == 3
