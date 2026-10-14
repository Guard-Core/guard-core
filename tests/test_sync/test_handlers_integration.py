import logging
import time
from collections.abc import Generator
from contextlib import contextmanager
from unittest.mock import MagicMock, patch

import pytest

from guard_core.exceptions import GuardRedisError
from guard_core.models import SecurityConfig
from guard_core.sync.handlers.ipban_handler import IPBanManager
from guard_core.sync.handlers.ratelimit_handler import RateLimitManager
from guard_core.sync.handlers.security_headers_handler import SecurityHeadersManager
from tests.test_sync.conftest import REDIS_URL, SyncMockGuardRequest


class _FailingConnection:
    def __init__(self, exc: BaseException) -> None:
        self._exc = exc

    def __enter__(self) -> None:
        raise self._exc

    def __exit__(self, *_args: object) -> None:
        return None


def test_ipban_initialize_redis() -> None:
    IPBanManager._instance = None
    mgr = IPBanManager()
    redis = MagicMock()
    mgr.initialize_redis(redis)
    assert mgr.redis_handler is redis


def test_ipban_is_banned_redis_expired() -> None:
    IPBanManager._instance = None
    mgr = IPBanManager()
    redis = MagicMock()
    redis.get_key = MagicMock(return_value=str(time.time() - 100))
    redis.delete = MagicMock()
    mgr.redis_handler = redis
    result = mgr.is_ip_banned("1.2.3.4")
    assert result is False
    redis.delete.assert_called_once()


def test_ipban_is_banned_redis_valid() -> None:
    IPBanManager._instance = None
    mgr = IPBanManager()
    redis = MagicMock()
    redis.get_key = MagicMock(return_value=str(time.time() + 1000))
    mgr.redis_handler = redis
    result = mgr.is_ip_banned("5.5.5.5")
    assert result is True


def test_ipban_reset_with_redis() -> None:
    IPBanManager._instance = None
    mgr = IPBanManager()
    mgr.config = MagicMock()
    mgr.config.redis_prefix = "test:"

    mock_conn = MagicMock()
    mock_conn.keys = MagicMock(return_value=["test:banned_ips:1.2.3.4"])
    mock_conn.delete = MagicMock()

    @contextmanager
    def mock_get_connection() -> Generator[MagicMock, None]:
        yield mock_conn

    redis = MagicMock()
    redis.get_connection = mock_get_connection
    redis.config = mgr.config
    mgr.redis_handler = redis
    mgr.reset()
    mock_conn.delete.assert_called_once()


def test_ipban_reset_with_redis_no_keys() -> None:
    IPBanManager._instance = None
    mgr = IPBanManager()
    mgr.config = MagicMock()
    mgr.config.redis_prefix = "test:"

    mock_conn = MagicMock()
    mock_conn.keys = MagicMock(return_value=[])
    mock_conn.delete = MagicMock()

    @contextmanager
    def mock_get_connection() -> Generator[MagicMock, None]:
        yield mock_conn

    redis = MagicMock()
    redis.get_connection = mock_get_connection
    redis.config = mgr.config
    mgr.redis_handler = redis
    mgr.reset()
    mock_conn.delete.assert_not_called()


def test_ipban_unban_with_redis() -> None:
    IPBanManager._instance = None
    mgr = IPBanManager()
    mgr.banned_ips["1.2.3.4"] = time.time() + 1000
    redis = MagicMock()
    redis.delete = MagicMock()
    mgr.redis_handler = redis
    mgr.unban_ip("1.2.3.4")
    redis.delete.assert_called_once()


def test_ipban_unban_with_agent() -> None:
    IPBanManager._instance = None
    mgr = IPBanManager()
    mgr.banned_ips["1.2.3.4"] = time.time() + 1000
    agent = MagicMock()
    agent.send_event = MagicMock()
    mgr.agent_handler = agent
    with patch(
        "guard_core.sync.handlers.ipban_handler.SecurityEvent", create=True
    ) as mock_event:
        mock_event.return_value = MagicMock()
        mgr.unban_ip("1.2.3.4")
    agent.send_event.assert_called_once()


def test_ipban_unban_agent_exception() -> None:
    IPBanManager._instance = None
    mgr = IPBanManager()
    mgr.banned_ips["1.2.3.4"] = time.time() + 1000
    agent = MagicMock()
    agent.send_event = MagicMock(side_effect=Exception("fail"))
    mgr.agent_handler = agent
    with patch("guard_core.sync.handlers.ipban_handler.SecurityEvent", create=True):
        mgr.unban_ip("1.2.3.4")


def test_ratelimit_initialize_redis() -> None:
    config = SecurityConfig(enable_redis=True, redis_url="redis://localhost:6379")
    mgr = RateLimitManager(config)

    mock_conn = MagicMock()
    mock_conn.script_load = MagicMock(return_value="sha123")

    @contextmanager
    def mock_get_connection() -> Generator[MagicMock, None]:
        yield mock_conn

    redis = MagicMock()
    redis.get_connection = mock_get_connection
    mgr.redis_handler = redis
    mgr.initialize_redis(redis)
    assert mgr.rate_limit_script_sha == "sha123"


def test_ratelimit_initialize_redis_exception() -> None:
    config = SecurityConfig(enable_redis=True, redis_url="redis://localhost:6379")
    mgr = RateLimitManager(config)

    redis = MagicMock()
    redis.get_connection = lambda: _FailingConnection(Exception("conn fail"))
    mgr.redis_handler = redis
    mgr.initialize_redis(redis)
    assert mgr.rate_limit_script_sha is None


def test_ratelimit_redis_count_with_script() -> None:
    config = SecurityConfig(enable_redis=True, redis_url="redis://localhost:6379")
    mgr = RateLimitManager(config)
    mgr.rate_limit_script_sha = "sha123"

    mock_conn = MagicMock()
    mock_conn.evalsha = MagicMock(return_value=5)

    @contextmanager
    def mock_get_connection() -> Generator[MagicMock, None]:
        yield mock_conn

    redis = MagicMock()
    redis.get_connection = mock_get_connection
    redis.config = MagicMock()
    redis.config.redis_prefix = "test:"
    mgr.redis_handler = redis

    count = mgr._get_redis_request_count("1.2.3.4", time.time(), time.time() - 60)
    assert count == 5


def test_ratelimit_redis_count_without_script() -> None:
    config = SecurityConfig(enable_redis=True, redis_url="redis://localhost:6379")
    mgr = RateLimitManager(config)
    mgr.rate_limit_script_sha = None

    mock_pipeline = MagicMock()
    mock_pipeline.zadd = MagicMock()
    mock_pipeline.zremrangebyscore = MagicMock()
    mock_pipeline.zcard = MagicMock()
    mock_pipeline.expire = MagicMock()
    mock_pipeline.execute = MagicMock(return_value=[1, 0, 3, True])

    mock_conn = MagicMock()
    mock_conn.pipeline = MagicMock(return_value=mock_pipeline)

    @contextmanager
    def mock_get_connection() -> Generator[MagicMock, None]:
        yield mock_conn

    redis = MagicMock()
    redis.get_connection = mock_get_connection
    redis.config = MagicMock()
    redis.config.redis_prefix = "test:"
    mgr.redis_handler = redis

    count = mgr._get_redis_request_count("1.2.3.4", time.time(), time.time() - 60)
    assert count == 3


def test_ratelimit_redis_error_raises_when_fail_open_false() -> None:
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
        mgr._get_redis_request_count("1.2.3.4", time.time(), time.time() - 60)


def test_ratelimit_redis_error_falls_back_when_fail_open_true() -> None:
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

    count = mgr._get_redis_request_count("1.2.3.4", time.time(), time.time() - 60)
    assert count is None


def test_ratelimit_generic_error_raises_when_fail_open_false() -> None:
    config = SecurityConfig(enable_redis=True, redis_url="redis://localhost:6379")
    mgr = RateLimitManager(config)
    mgr.rate_limit_script_sha = "sha123"

    redis = MagicMock()
    redis.get_connection = lambda: _FailingConnection(Exception("generic fail"))
    redis.config = MagicMock()
    redis.config.redis_prefix = "test:"
    mgr.redis_handler = redis

    with pytest.raises(GuardRedisError):
        mgr._get_redis_request_count("1.2.3.4", time.time(), time.time() - 60)


def test_ratelimit_generic_error_falls_back_when_fail_open_true() -> None:
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

    count = mgr._get_redis_request_count("1.2.3.4", time.time(), time.time() - 60)
    assert count is None


def test_ratelimit_in_memory_with_endpoint() -> None:
    config = SecurityConfig(enable_redis=False)
    mgr = RateLimitManager(config)
    current = time.time()
    count = mgr._get_in_memory_request_count("1.2.3.4", current - 60, current, "/api")
    assert count == 0


def test_ratelimit_check_disabled() -> None:
    config = SecurityConfig(enable_redis=False, enable_rate_limiting=False)
    mgr = RateLimitManager(config)
    req = SyncMockGuardRequest()
    result = mgr.check_rate_limit(req, "1.2.3.4", MagicMock())
    assert result is None


def test_ratelimit_check_redis_exceeded() -> None:
    config = SecurityConfig(
        enable_redis=True, redis_url="redis://localhost:6379", rate_limit=5
    )
    mgr = RateLimitManager(config)

    mock_conn = MagicMock()
    mock_conn.evalsha = MagicMock(return_value=10)

    @contextmanager
    def mock_get_connection() -> Generator[MagicMock, None]:
        yield mock_conn

    redis = MagicMock()
    redis.get_connection = mock_get_connection
    redis.config = MagicMock()
    redis.config.redis_prefix = "test:"
    mgr.redis_handler = redis
    mgr.rate_limit_script_sha = "sha123"

    from tests.test_sync.conftest import MockGuardResponse

    req = SyncMockGuardRequest()
    create_error = MagicMock(return_value=MockGuardResponse("rate limited", 429))

    with patch("guard_core.sync.handlers.ratelimit_handler.log_activity"):
        result = mgr.check_rate_limit(req, "1.2.3.4", create_error)
    assert result is not None
    assert result.status_code == 429


def test_ratelimit_check_redis_ok() -> None:
    config = SecurityConfig(
        enable_redis=True, redis_url="redis://localhost:6379", rate_limit=100
    )
    mgr = RateLimitManager(config)

    mock_conn = MagicMock()
    mock_conn.evalsha = MagicMock(return_value=2)

    @contextmanager
    def mock_get_connection() -> Generator[MagicMock, None]:
        yield mock_conn

    redis = MagicMock()
    redis.get_connection = mock_get_connection
    redis.config = MagicMock()
    redis.config.redis_prefix = "test:"
    mgr.redis_handler = redis
    mgr.rate_limit_script_sha = "sha123"

    req = SyncMockGuardRequest()
    result = mgr.check_rate_limit(req, "1.2.3.4", MagicMock())
    assert result is None


def test_ratelimit_check_raises_on_redis_error_when_fail_open_false() -> None:
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

    req = SyncMockGuardRequest()
    with pytest.raises(GuardRedisError):
        mgr.check_rate_limit(req, "1.2.3.4", MagicMock())
    assert "1.2.3.4" not in mgr.request_timestamps


def test_ratelimit_check_falls_back_to_memory_when_fail_open_true() -> None:
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

    req = SyncMockGuardRequest()
    result = mgr.check_rate_limit(req, "1.2.3.4", MagicMock())
    assert result is None
    assert len(mgr.request_timestamps["1.2.3.4"]) == 1


def test_ratelimit_reset_redis() -> None:
    config = SecurityConfig(enable_redis=True, redis_url="redis://localhost:6379")
    mgr = RateLimitManager(config)
    redis = MagicMock()
    redis.keys = MagicMock(return_value=["key1"])
    redis.delete_pattern = MagicMock()
    mgr.redis_handler = redis
    mgr.reset()
    redis.delete_pattern.assert_called_once()


def test_ratelimit_reset_redis_exception() -> None:
    config = SecurityConfig(enable_redis=True, redis_url="redis://localhost:6379")
    mgr = RateLimitManager(config)
    redis = MagicMock()
    redis.keys = MagicMock(side_effect=Exception("fail"))
    mgr.redis_handler = redis
    mgr.reset()


def test_ratelimit_send_event() -> None:
    config = SecurityConfig(enable_redis=False)
    mgr = RateLimitManager(config)
    agent = MagicMock()
    agent.send_event = MagicMock()
    mgr.agent_handler = agent
    req = SyncMockGuardRequest()
    with patch(
        "guard_core.sync.handlers.ratelimit_handler.SecurityEvent", create=True
    ) as mock_event:
        mock_event.return_value = MagicMock()
        mgr._send_rate_limit_event(req, "1.2.3.4", 10)
    agent.send_event.assert_called_once()


def test_ratelimit_send_event_exception() -> None:
    config = SecurityConfig(enable_redis=False)
    mgr = RateLimitManager(config)
    agent = MagicMock()
    agent.send_event = MagicMock(side_effect=Exception("fail"))
    mgr.agent_handler = agent
    req = SyncMockGuardRequest()
    with patch("guard_core.sync.handlers.ratelimit_handler.SecurityEvent", create=True):
        mgr._send_rate_limit_event(req, "1.2.3.4", 10)


def test_ratelimit_redis_count_with_endpoint() -> None:
    config = SecurityConfig(enable_redis=True, redis_url="redis://localhost:6379")
    mgr = RateLimitManager(config)
    mgr.rate_limit_script_sha = "sha123"

    mock_conn = MagicMock()
    mock_conn.evalsha = MagicMock(return_value=2)

    @contextmanager
    def mock_get_connection() -> Generator[MagicMock, None]:
        yield mock_conn

    redis = MagicMock()
    redis.get_connection = mock_get_connection
    redis.config = MagicMock()
    redis.config.redis_prefix = "test:"
    mgr.redis_handler = redis

    count = mgr._get_redis_request_count(
        "1.2.3.4", time.time(), time.time() - 60, endpoint_path="/api"
    )
    assert count == 2


def test_security_headers_cors_wildcard_credentials() -> None:
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


def test_security_headers_update_content_type_options() -> None:
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


def test_security_headers_update_xss_protection() -> None:
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


def test_security_headers_permissions_policy_set() -> None:
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


def test_security_headers_permissions_policy_remove() -> None:
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


def test_security_headers_get_headers_with_agent() -> None:
    SecurityHeadersManager._instance = None
    mgr = SecurityHeadersManager()
    mgr.headers_cache.clear()
    agent = MagicMock()
    agent.send_event = MagicMock()
    mgr.agent_handler = agent
    with patch.object(mgr, "_send_headers_applied_event") as mock_send:
        headers = mgr.get_headers("/test")
    mock_send.assert_called_once()
    assert isinstance(headers, dict)


def test_security_headers_wildcard_with_credentials_cors() -> None:
    SecurityHeadersManager._instance = None
    mgr = SecurityHeadersManager()
    mgr.cors_config = {
        "origins": ["*"],
        "allow_credentials": True,
        "allow_methods": ["GET"],
        "allow_headers": ["*"],
    }
    result = mgr.get_cors_headers("https://example.com")
    assert result == {}


def test_security_headers_cors_invalid_methods_type() -> None:
    SecurityHeadersManager._instance = None
    mgr = SecurityHeadersManager()
    mgr.cors_config = {
        "origins": ["https://example.com"],
        "allow_credentials": False,
        "allow_methods": "GET",
        "allow_headers": ["*"],
    }
    result = mgr.get_cors_headers("https://example.com")
    assert "Access-Control-Allow-Methods" in result


def test_security_headers_cors_invalid_headers_type() -> None:
    SecurityHeadersManager._instance = None
    mgr = SecurityHeadersManager()
    mgr.cors_config = {
        "origins": ["https://example.com"],
        "allow_credentials": False,
        "allow_methods": ["GET"],
        "allow_headers": "*",
    }
    result = mgr.get_cors_headers("https://example.com")
    assert "Access-Control-Allow-Headers" in result


def test_security_headers_cors_non_list_origins() -> None:
    SecurityHeadersManager._instance = None
    mgr = SecurityHeadersManager()
    mgr.cors_config = {
        "origins": "not a list",
        "allow_credentials": False,
    }
    result = mgr.get_cors_headers("https://example.com")
    assert result == {}


def test_security_headers_cors_origin_not_allowed() -> None:
    SecurityHeadersManager._instance = None
    mgr = SecurityHeadersManager()
    mgr.cors_config = {
        "origins": ["https://allowed.com"],
        "allow_credentials": False,
        "allow_methods": ["GET"],
        "allow_headers": ["*"],
    }
    result = mgr.get_cors_headers("https://evil.com")
    assert result == {}


def test_cloud_handler_get_details_invalid_ip() -> None:
    from guard_core.sync.handlers.cloud_handler import CloudManager

    handler = CloudManager()
    result = handler.get_cloud_provider_details("not_valid_ip")
    assert result is None


def test_redis_handler_keys_disabled() -> None:
    from guard_core.sync.handlers.redis_handler import RedisManager

    config = SecurityConfig(enable_redis=False)
    mgr = RedisManager(config)
    result = mgr.keys("test*")
    assert result is None


def test_redis_handler_delete_pattern_disabled() -> None:
    from guard_core.sync.handlers.redis_handler import RedisManager

    config = SecurityConfig(enable_redis=False)
    mgr = RedisManager(config)
    result = mgr.delete_pattern("test*")
    assert result is None


def test_redis_handler_keys_with_redis() -> None:
    from guard_core.sync.handlers.redis_handler import RedisManager

    config = SecurityConfig(enable_redis=True, redis_url=REDIS_URL)
    mgr = RedisManager(config)
    mgr.initialize()
    result = mgr.keys("nonexistent_pattern_xyz*")
    assert result is not None
    assert isinstance(result, list)
    mgr.close()


def test_redis_handler_delete_pattern_with_redis() -> None:
    from guard_core.sync.handlers.redis_handler import RedisManager

    config = SecurityConfig(enable_redis=True, redis_url=REDIS_URL)
    mgr = RedisManager(config)
    mgr.initialize()
    result = mgr.delete_pattern("nonexistent_pattern_xyz*")
    assert result is not None
    mgr.close()


def test_ratelimit_handle_exceeded_with_agent() -> None:
    config = SecurityConfig(enable_redis=False)
    mgr = RateLimitManager(config)
    agent = MagicMock()
    agent.send_event = MagicMock()
    mgr.agent_handler = agent
    req = SyncMockGuardRequest()

    from tests.test_sync.conftest import MockGuardResponse

    create_error = MagicMock(return_value=MockGuardResponse("rate limited", 429))
    with patch("guard_core.sync.handlers.ratelimit_handler.log_activity"):
        with patch(
            "guard_core.sync.handlers.ratelimit_handler.SecurityEvent", create=True
        ):
            result = mgr._handle_rate_limit_exceeded(req, "1.2.3.4", 10, create_error)
    assert result.status_code == 429


def test_ratelimit_exceeded_passive_log_names_rate_limit(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SecurityConfig(enable_redis=False, passive_mode=True)
    mgr = RateLimitManager(config)
    req = SyncMockGuardRequest()

    from tests.test_sync.conftest import MockGuardResponse

    create_error = MagicMock(return_value=MockGuardResponse("rate limited", 429))
    with caplog.at_level(logging.WARNING):
        mgr._handle_rate_limit_exceeded(req, "1.2.3.4", 10, create_error)
    assert "Rate limit exceeded for IP: 1.2.3.4" in caplog.text
    assert "Penetration attempt" not in caplog.text


def test_responses_factory_cors_disabled() -> None:
    from guard_core.sync.core.events.metrics import MetricsCollector
    from guard_core.sync.core.responses.context import ResponseContext
    from guard_core.sync.core.responses.factory import ErrorResponseFactory
    from tests.test_sync.conftest import MockGuardResponseFactory

    config = SecurityConfig(enable_redis=False, security_headers={"enabled": False})
    metrics = MagicMock(spec=MetricsCollector)
    metrics.collect_request_metrics = MagicMock()
    ctx = ResponseContext(
        config=config,
        logger=MagicMock(),
        metrics_collector=metrics,
        response_factory=MockGuardResponseFactory(),
    )
    factory = ErrorResponseFactory(ctx)
    from tests.test_sync.conftest import MockGuardResponse

    resp = MockGuardResponse("ok", 200)
    result = factory.apply_cors_headers(resp, "https://example.com")
    assert result is resp
