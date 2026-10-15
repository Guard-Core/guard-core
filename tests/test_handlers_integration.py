import logging
import time
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from guard_core.exceptions import GuardRedisError
from guard_core.handlers.ipban_handler import IPBanManager
from guard_core.handlers.ratelimit_handler import RateLimitManager
from guard_core.handlers.security_headers_handler import SecurityHeadersManager
from guard_core.models import SecurityConfig
from tests.conftest import REDIS_URL, MockGuardRequest


class _FailingConnection:
    def __init__(self, exc: BaseException) -> None:
        self._exc = exc

    async def __aenter__(self) -> None:
        raise self._exc

    async def __aexit__(self, *_args: object) -> None:
        return None


async def test_ipban_initialize_redis() -> None:
    IPBanManager._instance = None
    mgr = IPBanManager()
    redis = MagicMock()
    await mgr.initialize_redis(redis)
    assert mgr.redis_handler is redis


async def test_ipban_is_banned_redis_expired() -> None:
    IPBanManager._instance = None
    mgr = IPBanManager()
    redis = MagicMock()
    redis.get_key = AsyncMock(return_value=str(time.time() - 100))
    redis.delete = AsyncMock()
    mgr.redis_handler = redis
    result = await mgr.is_ip_banned("1.2.3.4")
    assert result is False
    redis.delete.assert_called_once()


async def test_ipban_is_banned_redis_valid() -> None:
    IPBanManager._instance = None
    mgr = IPBanManager()
    redis = MagicMock()
    redis.get_key = AsyncMock(return_value=str(time.time() + 1000))
    mgr.redis_handler = redis
    result = await mgr.is_ip_banned("5.5.5.5")
    assert result is True


async def test_ipban_reset_with_redis() -> None:
    IPBanManager._instance = None
    mgr = IPBanManager()
    mgr.config = MagicMock()
    mgr.config.redis_prefix = "test:"

    mock_conn = MagicMock()
    mock_conn.keys = AsyncMock(return_value=["test:banned_ips:1.2.3.4"])
    mock_conn.delete = AsyncMock()

    @asynccontextmanager
    async def mock_get_connection() -> AsyncGenerator[MagicMock, None]:
        yield mock_conn

    redis = MagicMock()
    redis.get_connection = mock_get_connection
    redis.config = mgr.config
    mgr.redis_handler = redis
    await mgr.reset()
    mock_conn.delete.assert_called_once()


async def test_ipban_reset_with_redis_no_keys() -> None:
    IPBanManager._instance = None
    mgr = IPBanManager()
    mgr.config = MagicMock()
    mgr.config.redis_prefix = "test:"

    mock_conn = MagicMock()
    mock_conn.keys = AsyncMock(return_value=[])
    mock_conn.delete = AsyncMock()

    @asynccontextmanager
    async def mock_get_connection() -> AsyncGenerator[MagicMock, None]:
        yield mock_conn

    redis = MagicMock()
    redis.get_connection = mock_get_connection
    redis.config = mgr.config
    mgr.redis_handler = redis
    await mgr.reset()
    mock_conn.delete.assert_not_called()


async def test_ipban_unban_with_redis() -> None:
    IPBanManager._instance = None
    mgr = IPBanManager()
    mgr.banned_ips["1.2.3.4"] = time.time() + 1000
    redis = MagicMock()
    redis.delete = AsyncMock()
    mgr.redis_handler = redis
    await mgr.unban_ip("1.2.3.4")
    redis.delete.assert_called_once()


async def test_ipban_unban_with_agent() -> None:
    IPBanManager._instance = None
    mgr = IPBanManager()
    mgr.banned_ips["1.2.3.4"] = time.time() + 1000
    agent = MagicMock()
    agent.send_event = AsyncMock()
    mgr.agent_handler = agent
    with patch(
        "guard_core.handlers.ipban_handler.SecurityEvent", create=True
    ) as mock_event:
        mock_event.return_value = MagicMock()
        await mgr.unban_ip("1.2.3.4")
    agent.send_event.assert_called_once()


async def test_ipban_unban_agent_exception() -> None:
    IPBanManager._instance = None
    mgr = IPBanManager()
    mgr.banned_ips["1.2.3.4"] = time.time() + 1000
    agent = MagicMock()
    agent.send_event = AsyncMock(side_effect=Exception("fail"))
    mgr.agent_handler = agent
    with patch("guard_core.handlers.ipban_handler.SecurityEvent", create=True):
        await mgr.unban_ip("1.2.3.4")


async def test_ratelimit_initialize_redis() -> None:
    config = SecurityConfig(enable_redis=True, redis_url="redis://localhost:6379")
    mgr = RateLimitManager(config)

    mock_conn = MagicMock()
    mock_conn.script_load = AsyncMock(return_value="sha123")

    @asynccontextmanager
    async def mock_get_connection() -> AsyncGenerator[MagicMock, None]:
        yield mock_conn

    redis = MagicMock()
    redis.get_connection = mock_get_connection
    mgr.redis_handler = redis
    await mgr.initialize_redis(redis)
    assert mgr.rate_limit_script_sha == "sha123"


async def test_ratelimit_initialize_redis_exception() -> None:
    config = SecurityConfig(enable_redis=True, redis_url="redis://localhost:6379")
    mgr = RateLimitManager(config)

    redis = MagicMock()
    redis.get_connection = lambda: _FailingConnection(Exception("conn fail"))
    mgr.redis_handler = redis
    await mgr.initialize_redis(redis)
    assert mgr.rate_limit_script_sha is None


async def test_ratelimit_redis_count_with_script() -> None:
    config = SecurityConfig(enable_redis=True, redis_url="redis://localhost:6379")
    mgr = RateLimitManager(config)
    mgr.rate_limit_script_sha = "sha123"

    mock_conn = MagicMock()
    mock_conn.evalsha = AsyncMock(return_value=5)

    @asynccontextmanager
    async def mock_get_connection() -> AsyncGenerator[MagicMock, None]:
        yield mock_conn

    redis = MagicMock()
    redis.get_connection = mock_get_connection
    redis.config = MagicMock()
    redis.config.redis_prefix = "test:"
    mgr.redis_handler = redis

    count = await mgr._get_redis_request_count("1.2.3.4", time.time(), time.time() - 60)
    assert count == 5


async def test_ratelimit_redis_count_without_script() -> None:
    config = SecurityConfig(enable_redis=True, redis_url="redis://localhost:6379")
    mgr = RateLimitManager(config)
    mgr.rate_limit_script_sha = None

    mock_pipeline = MagicMock()
    mock_pipeline.zadd = MagicMock()
    mock_pipeline.zremrangebyscore = MagicMock()
    mock_pipeline.zcard = MagicMock()
    mock_pipeline.expire = MagicMock()
    mock_pipeline.execute = AsyncMock(return_value=[1, 0, 3, True])

    mock_conn = MagicMock()
    mock_conn.pipeline = MagicMock(return_value=mock_pipeline)

    @asynccontextmanager
    async def mock_get_connection() -> AsyncGenerator[MagicMock, None]:
        yield mock_conn

    redis = MagicMock()
    redis.get_connection = mock_get_connection
    redis.config = MagicMock()
    redis.config.redis_prefix = "test:"
    mgr.redis_handler = redis

    count = await mgr._get_redis_request_count("1.2.3.4", time.time(), time.time() - 60)
    assert count == 3


async def test_ratelimit_redis_error_raises_when_fail_open_false() -> None:
    from redis.exceptions import RedisError

    config = SecurityConfig(enable_redis=True, redis_url="redis://localhost:6379")
    mgr = RateLimitManager(config)
    mgr.rate_limit_script_sha = "sha123"

    redis = MagicMock()
    redis.get_connection = lambda: _FailingConnection(RedisError("conn fail"))
    redis.config = MagicMock()
    redis.config.redis_prefix = "test:"
    mgr.redis_handler = redis

    with pytest.raises(GuardRedisError):
        await mgr._get_redis_request_count("1.2.3.4", time.time(), time.time() - 60)


async def test_ratelimit_redis_error_falls_back_when_fail_open_true() -> None:
    from redis.exceptions import RedisError

    config = SecurityConfig(
        enable_redis=True, redis_url="redis://localhost:6379", redis_fail_open=True
    )
    mgr = RateLimitManager(config)
    mgr.rate_limit_script_sha = "sha123"

    redis = MagicMock()
    redis.get_connection = lambda: _FailingConnection(RedisError("conn fail"))
    redis.config = MagicMock()
    redis.config.redis_prefix = "test:"
    mgr.redis_handler = redis

    count = await mgr._get_redis_request_count("1.2.3.4", time.time(), time.time() - 60)
    assert count is None


async def test_ratelimit_generic_error_raises_when_fail_open_false() -> None:
    config = SecurityConfig(enable_redis=True, redis_url="redis://localhost:6379")
    mgr = RateLimitManager(config)
    mgr.rate_limit_script_sha = "sha123"

    redis = MagicMock()
    redis.get_connection = lambda: _FailingConnection(Exception("generic fail"))
    redis.config = MagicMock()
    redis.config.redis_prefix = "test:"
    mgr.redis_handler = redis

    with pytest.raises(GuardRedisError):
        await mgr._get_redis_request_count("1.2.3.4", time.time(), time.time() - 60)


async def test_ratelimit_generic_error_falls_back_when_fail_open_true() -> None:
    config = SecurityConfig(
        enable_redis=True, redis_url="redis://localhost:6379", redis_fail_open=True
    )
    mgr = RateLimitManager(config)
    mgr.rate_limit_script_sha = "sha123"

    redis = MagicMock()
    redis.get_connection = lambda: _FailingConnection(Exception("generic fail"))
    redis.config = MagicMock()
    redis.config.redis_prefix = "test:"
    mgr.redis_handler = redis

    count = await mgr._get_redis_request_count("1.2.3.4", time.time(), time.time() - 60)
    assert count is None


async def test_ratelimit_in_memory_with_endpoint() -> None:
    config = SecurityConfig(enable_redis=False)
    mgr = RateLimitManager(config)
    current = time.time()
    count = mgr._get_in_memory_request_count("1.2.3.4", current - 60, current, "/api")
    assert count == 0


async def test_ratelimit_check_disabled() -> None:
    config = SecurityConfig(enable_redis=False, enable_rate_limiting=False)
    mgr = RateLimitManager(config)
    req = MockGuardRequest()
    result = await mgr.check_rate_limit(req, "1.2.3.4", AsyncMock())
    assert result is None


async def test_ratelimit_check_redis_exceeded() -> None:
    config = SecurityConfig(
        enable_redis=True, redis_url="redis://localhost:6379", rate_limit=5
    )
    mgr = RateLimitManager(config)

    mock_conn = MagicMock()
    mock_conn.evalsha = AsyncMock(return_value=10)

    @asynccontextmanager
    async def mock_get_connection() -> AsyncGenerator[MagicMock, None]:
        yield mock_conn

    redis = MagicMock()
    redis.get_connection = mock_get_connection
    redis.config = MagicMock()
    redis.config.redis_prefix = "test:"
    mgr.redis_handler = redis
    mgr.rate_limit_script_sha = "sha123"

    from tests.conftest import MockGuardResponse

    req = MockGuardRequest()
    create_error = AsyncMock(return_value=MockGuardResponse("rate limited", 429))

    with patch(
        "guard_core.handlers.ratelimit_handler.log_activity", new_callable=AsyncMock
    ):
        result = await mgr.check_rate_limit(req, "1.2.3.4", create_error)
    assert result is not None
    assert result.status_code == 429


async def test_ratelimit_check_redis_ok() -> None:
    config = SecurityConfig(
        enable_redis=True, redis_url="redis://localhost:6379", rate_limit=100
    )
    mgr = RateLimitManager(config)

    mock_conn = MagicMock()
    mock_conn.evalsha = AsyncMock(return_value=2)

    @asynccontextmanager
    async def mock_get_connection() -> AsyncGenerator[MagicMock, None]:
        yield mock_conn

    redis = MagicMock()
    redis.get_connection = mock_get_connection
    redis.config = MagicMock()
    redis.config.redis_prefix = "test:"
    mgr.redis_handler = redis
    mgr.rate_limit_script_sha = "sha123"

    req = MockGuardRequest()
    result = await mgr.check_rate_limit(req, "1.2.3.4", AsyncMock())
    assert result is None


async def test_ratelimit_check_raises_on_redis_error_when_fail_open_false() -> None:
    from redis.exceptions import RedisError

    config = SecurityConfig(
        enable_redis=True, redis_url="redis://localhost:6379", rate_limit=100
    )
    mgr = RateLimitManager(config)

    redis = MagicMock()
    redis.get_connection = lambda: _FailingConnection(RedisError("conn fail"))
    redis.config = MagicMock()
    redis.config.redis_prefix = "test:"
    mgr.redis_handler = redis
    mgr.rate_limit_script_sha = "sha123"

    req = MockGuardRequest()
    with pytest.raises(GuardRedisError):
        await mgr.check_rate_limit(req, "1.2.3.4", AsyncMock())
    assert "1.2.3.4" not in mgr.request_timestamps


async def test_ratelimit_check_falls_back_to_memory_when_fail_open_true() -> None:
    from redis.exceptions import RedisError

    config = SecurityConfig(
        enable_redis=True,
        redis_url="redis://localhost:6379",
        rate_limit=100,
        redis_fail_open=True,
    )
    mgr = RateLimitManager(config)

    redis = MagicMock()
    redis.get_connection = lambda: _FailingConnection(RedisError("conn fail"))
    redis.config = MagicMock()
    redis.config.redis_prefix = "test:"
    mgr.redis_handler = redis
    mgr.rate_limit_script_sha = "sha123"

    req = MockGuardRequest()
    result = await mgr.check_rate_limit(req, "1.2.3.4", AsyncMock())
    assert result is None
    assert len(mgr.request_timestamps["1.2.3.4"]) == 1


async def test_ratelimit_reset_redis() -> None:
    config = SecurityConfig(enable_redis=True, redis_url="redis://localhost:6379")
    mgr = RateLimitManager(config)
    redis = MagicMock()
    redis.keys = AsyncMock(return_value=["key1"])
    redis.delete_pattern = AsyncMock()
    mgr.redis_handler = redis
    await mgr.reset()
    redis.delete_pattern.assert_called_once()


async def test_ratelimit_reset_redis_exception() -> None:
    config = SecurityConfig(enable_redis=True, redis_url="redis://localhost:6379")
    mgr = RateLimitManager(config)
    redis = MagicMock()
    redis.keys = AsyncMock(side_effect=Exception("fail"))
    mgr.redis_handler = redis
    await mgr.reset()


async def test_ratelimit_send_event() -> None:
    config = SecurityConfig(enable_redis=False)
    mgr = RateLimitManager(config)
    agent = MagicMock()
    agent.send_event = AsyncMock()
    mgr.agent_handler = agent
    req = MockGuardRequest()
    with patch(
        "guard_core.handlers.ratelimit_handler.SecurityEvent", create=True
    ) as mock_event:
        mock_event.return_value = MagicMock()
        await mgr._send_rate_limit_event(req, "1.2.3.4", 10)
    agent.send_event.assert_called_once()


async def test_ratelimit_send_event_exception() -> None:
    config = SecurityConfig(enable_redis=False)
    mgr = RateLimitManager(config)
    agent = MagicMock()
    agent.send_event = AsyncMock(side_effect=Exception("fail"))
    mgr.agent_handler = agent
    req = MockGuardRequest()
    with patch("guard_core.handlers.ratelimit_handler.SecurityEvent", create=True):
        await mgr._send_rate_limit_event(req, "1.2.3.4", 10)


async def test_ratelimit_redis_count_with_endpoint() -> None:
    config = SecurityConfig(enable_redis=True, redis_url="redis://localhost:6379")
    mgr = RateLimitManager(config)
    mgr.rate_limit_script_sha = "sha123"

    mock_conn = MagicMock()
    mock_conn.evalsha = AsyncMock(return_value=2)

    @asynccontextmanager
    async def mock_get_connection() -> AsyncGenerator[MagicMock, None]:
        yield mock_conn

    redis = MagicMock()
    redis.get_connection = mock_get_connection
    redis.config = MagicMock()
    redis.config.redis_prefix = "test:"
    mgr.redis_handler = redis

    count = await mgr._get_redis_request_count(
        "1.2.3.4", time.time(), time.time() - 60, endpoint_path="/api"
    )
    assert count == 2


async def test_security_headers_cors_wildcard_credentials() -> None:
    SecurityHeadersManager._instance = None
    mgr = SecurityHeadersManager()
    mgr._configure_cors(
        cors_origins=["*"],
        cors_allow_credentials=True,
        cors_allow_methods=None,
        cors_allow_headers=None,
    )
    assert mgr.cors_config is not None
    assert mgr.cors_config["allow_credentials"] is False


async def test_security_headers_update_content_type_options() -> None:
    SecurityHeadersManager._instance = None
    mgr = SecurityHeadersManager()
    mgr._update_default_headers(
        frame_options=None,
        content_type_options="nosniff",
        xss_protection=None,
        referrer_policy=None,
        permissions_policy="UNSET",
    )
    assert mgr.default_headers["X-Content-Type-Options"] == "nosniff"


async def test_security_headers_update_xss_protection() -> None:
    SecurityHeadersManager._instance = None
    mgr = SecurityHeadersManager()
    mgr._update_default_headers(
        frame_options=None,
        content_type_options=None,
        xss_protection="0",
        referrer_policy=None,
        permissions_policy="UNSET",
    )
    assert mgr.default_headers["X-XSS-Protection"] == "0"


async def test_security_headers_permissions_policy_set() -> None:
    SecurityHeadersManager._instance = None
    mgr = SecurityHeadersManager()
    mgr._update_default_headers(
        frame_options=None,
        content_type_options=None,
        xss_protection=None,
        referrer_policy=None,
        permissions_policy="camera=()",
    )
    assert mgr.default_headers["Permissions-Policy"] == "camera=()"


async def test_security_headers_permissions_policy_remove() -> None:
    SecurityHeadersManager._instance = None
    mgr = SecurityHeadersManager()
    mgr.default_headers["Permissions-Policy"] = "geolocation=()"
    mgr._update_default_headers(
        frame_options=None,
        content_type_options=None,
        xss_protection=None,
        referrer_policy=None,
        permissions_policy=None,
    )
    assert "Permissions-Policy" not in mgr.default_headers


async def test_security_headers_get_headers_with_agent() -> None:
    SecurityHeadersManager._instance = None
    mgr = SecurityHeadersManager()
    mgr.headers_cache.clear()
    agent = MagicMock()
    agent.send_event = AsyncMock()
    mgr.agent_handler = agent
    with patch.object(
        mgr, "_send_headers_applied_event", new_callable=AsyncMock
    ) as mock_send:
        headers = await mgr.get_headers("/test")
    mock_send.assert_called_once()
    assert isinstance(headers, dict)


async def test_security_headers_wildcard_with_credentials_cors() -> None:
    SecurityHeadersManager._instance = None
    mgr = SecurityHeadersManager()
    mgr.cors_config = {
        "origins": ["*"],
        "allow_credentials": True,
        "allow_methods": ["GET"],
        "allow_headers": ["*"],
    }
    result = await mgr.get_cors_headers("https://example.com")
    assert result == {}


async def test_security_headers_cors_invalid_methods_type() -> None:
    SecurityHeadersManager._instance = None
    mgr = SecurityHeadersManager()
    mgr.cors_config = {
        "origins": ["https://example.com"],
        "allow_credentials": False,
        "allow_methods": "GET",
        "allow_headers": ["*"],
    }
    result = await mgr.get_cors_headers("https://example.com")
    assert "Access-Control-Allow-Methods" in result


async def test_security_headers_cors_invalid_headers_type() -> None:
    SecurityHeadersManager._instance = None
    mgr = SecurityHeadersManager()
    mgr.cors_config = {
        "origins": ["https://example.com"],
        "allow_credentials": False,
        "allow_methods": ["GET"],
        "allow_headers": "*",
    }
    result = await mgr.get_cors_headers("https://example.com")
    assert "Access-Control-Allow-Headers" in result


async def test_security_headers_cors_non_list_origins() -> None:
    SecurityHeadersManager._instance = None
    mgr = SecurityHeadersManager()
    mgr.cors_config = {
        "origins": "not a list",
        "allow_credentials": False,
    }
    result = await mgr.get_cors_headers("https://example.com")
    assert result == {}


async def test_security_headers_cors_origin_not_allowed() -> None:
    SecurityHeadersManager._instance = None
    mgr = SecurityHeadersManager()
    mgr.cors_config = {
        "origins": ["https://allowed.com"],
        "allow_credentials": False,
        "allow_methods": ["GET"],
        "allow_headers": ["*"],
    }
    result = await mgr.get_cors_headers("https://evil.com")
    assert result == {}


async def test_cloud_handler_get_details_invalid_ip() -> None:
    from guard_core.handlers.cloud_handler import CloudManager

    handler = CloudManager()
    result = handler.get_cloud_provider_details("not_valid_ip")
    assert result is None


async def test_redis_handler_keys_disabled() -> None:
    from guard_core.handlers.redis_handler import RedisManager

    config = SecurityConfig(enable_redis=False)
    mgr = RedisManager(config)
    result = await mgr.keys("test*")
    assert result is None


async def test_redis_handler_delete_pattern_disabled() -> None:
    from guard_core.handlers.redis_handler import RedisManager

    config = SecurityConfig(enable_redis=False)
    mgr = RedisManager(config)
    result = await mgr.delete_pattern("test*")
    assert result is None


async def test_redis_handler_keys_with_redis() -> None:
    from guard_core.handlers.redis_handler import RedisManager

    config = SecurityConfig(enable_redis=True, redis_url=REDIS_URL)
    mgr = RedisManager(config)
    await mgr.initialize()
    result = await mgr.keys("nonexistent_pattern_xyz*")
    assert result is not None
    assert isinstance(result, list)
    await mgr.close()


async def test_redis_handler_delete_pattern_with_redis() -> None:
    from guard_core.handlers.redis_handler import RedisManager

    config = SecurityConfig(enable_redis=True, redis_url=REDIS_URL)
    mgr = RedisManager(config)
    await mgr.initialize()
    result = await mgr.delete_pattern("nonexistent_pattern_xyz*")
    assert result is not None
    await mgr.close()


async def test_ratelimit_handle_exceeded_with_agent() -> None:
    config = SecurityConfig(enable_redis=False)
    mgr = RateLimitManager(config)
    agent = MagicMock()
    agent.send_event = AsyncMock()
    mgr.agent_handler = agent
    req = MockGuardRequest()

    from tests.conftest import MockGuardResponse

    create_error = AsyncMock(return_value=MockGuardResponse("rate limited", 429))
    with patch(
        "guard_core.handlers.ratelimit_handler.log_activity", new_callable=AsyncMock
    ):
        with patch("guard_core.handlers.ratelimit_handler.SecurityEvent", create=True):
            result = await mgr._handle_rate_limit_exceeded(
                req, "1.2.3.4", 10, create_error
            )
    assert result.status_code == 429


async def test_ratelimit_exceeded_passive_log_names_rate_limit(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SecurityConfig(enable_redis=False, passive_mode=True)
    mgr = RateLimitManager(config)
    req = MockGuardRequest()

    from tests.conftest import MockGuardResponse

    create_error = AsyncMock(return_value=MockGuardResponse("rate limited", 429))
    with caplog.at_level(logging.WARNING):
        await mgr._handle_rate_limit_exceeded(req, "1.2.3.4", 10, create_error)
    assert "Rate limit exceeded for IP: 1.2.3.4" in caplog.text
    assert "Penetration attempt" not in caplog.text


async def test_responses_factory_cors_disabled() -> None:
    from guard_core.core.events.metrics import MetricsCollector
    from guard_core.core.responses.context import ResponseContext
    from guard_core.core.responses.factory import ErrorResponseFactory
    from tests.conftest import MockGuardResponseFactory

    config = SecurityConfig(enable_redis=False, security_headers={"enabled": False})
    metrics = MagicMock(spec=MetricsCollector)
    metrics.collect_request_metrics = AsyncMock()
    ctx = ResponseContext(
        config=config,
        logger=MagicMock(),
        metrics_collector=metrics,
        response_factory=MockGuardResponseFactory(),
    )
    factory = ErrorResponseFactory(ctx)
    from tests.conftest import MockGuardResponse

    resp = MockGuardResponse("ok", 200)
    result = await factory.apply_cors_headers(resp, "https://example.com")
    assert result is resp
