import logging
import time
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from guard_core.exceptions import GuardRedisError
from guard_core.handlers.ipban_handler import IPBanManager
from guard_core.handlers.ratelimit_handler import (
    RateLimitManager,
    RateLimitTier,
    RateLimitVerdict,
    _in_memory_tier_verdict,
)
from guard_core.handlers.security_headers_handler import SecurityHeadersManager
from guard_core.models import SecurityConfig
from tests.conftest import REDIS_URL, MockGuardRequest
from tests.ipban_redis_fake import fake_ban_redis


def _scan_iter_of(keys: list[str]) -> Any:
    async def scan_iter(*_args: Any, **_kwargs: Any) -> Any:
        for key in keys:
            yield str(key)

    return scan_iter


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
    redis = fake_ban_redis(str(time.time() - 100))
    mgr.redis_handler = redis
    result = await mgr.is_ip_banned("1.2.3.4")
    assert result is False
    redis.delete.assert_called_once()


async def test_ipban_is_banned_redis_valid() -> None:
    IPBanManager._instance = None
    mgr = IPBanManager()
    mgr.redis_handler = fake_ban_redis(str(time.time() + 1000))
    result = await mgr.is_ip_banned("5.5.5.5")
    assert result is True


async def test_ipban_reset_with_redis() -> None:
    IPBanManager._instance = None
    mgr = IPBanManager()
    mgr.config = MagicMock()
    mgr.config.redis_prefix = "test:"

    mock_conn = MagicMock()
    mock_conn.scan_iter = _scan_iter_of(["test:banned_ips:1.2.3.4"])
    mock_conn.unlink = AsyncMock()

    @asynccontextmanager
    async def mock_get_connection() -> AsyncGenerator[MagicMock, None]:
        yield mock_conn

    redis = MagicMock()
    redis.get_connection = mock_get_connection
    redis.config = mgr.config
    mgr.redis_handler = redis
    await mgr.reset()
    assert mock_conn.unlink.call_args_list[0].args == ("test:banned_ips:1.2.3.4",)


async def test_ipban_reset_with_redis_no_keys() -> None:
    IPBanManager._instance = None
    mgr = IPBanManager()
    mgr.config = MagicMock()
    mgr.config.redis_prefix = "test:"

    mock_conn = MagicMock()
    mock_conn.scan_iter = _scan_iter_of([])
    mock_conn.unlink = AsyncMock()

    @asynccontextmanager
    async def mock_get_connection() -> AsyncGenerator[MagicMock, None]:
        yield mock_conn

    redis = MagicMock()
    redis.get_connection = mock_get_connection
    redis.config = mgr.config
    mgr.redis_handler = redis
    await mgr.reset()
    mock_conn.unlink.assert_not_called()


async def test_ipban_unban_with_redis() -> None:
    IPBanManager._instance = None
    mgr = IPBanManager()
    mgr.banned_ips["1.2.3.4"] = time.time() + 1000
    redis = MagicMock()
    redis.delete = AsyncMock()
    redis.forget_detection_strikes = AsyncMock()
    mgr.redis_handler = redis
    await mgr.unban_ip("1.2.3.4")
    redis.delete.assert_any_call("banned_ips", "1.2.3.4")
    redis.delete.assert_any_call("rate_limit", "violations:1.2.3.4")
    redis.forget_detection_strikes.assert_called_once_with("1.2.3.4")


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


async def _global_verdict(mgr: RateLimitManager) -> RateLimitVerdict:
    return await mgr._tier_verdict(
        "1.2.3.4", [RateLimitTier("global", 10, 60)], mgr.config
    )


async def test_ratelimit_redis_count_with_script() -> None:
    config = SecurityConfig(enable_redis=True, redis_url="redis://localhost:6379")
    mgr = RateLimitManager(config)
    mgr.rate_limit_script_sha = "sha123"

    mock_conn = MagicMock()
    mock_conn.evalsha = AsyncMock(return_value=[1, 5, 12])

    @asynccontextmanager
    async def mock_get_connection() -> AsyncGenerator[MagicMock, None]:
        yield mock_conn

    redis = MagicMock()
    redis.get_connection = mock_get_connection
    redis.config = MagicMock()
    redis.config.redis_prefix = "test:"
    mgr.redis_handler = redis

    verdict = await _global_verdict(mgr)
    assert verdict == RateLimitVerdict(0, 6, 12)
    mock_conn.evalsha.assert_awaited_once_with(
        "sha123", 1, "test:rate_limit:rate:1.2.3.4", 10, 60
    )


async def test_ratelimit_redis_count_without_script() -> None:
    config = SecurityConfig(enable_redis=True, redis_url="redis://localhost:6379")
    mgr = RateLimitManager(config)
    mgr.rate_limit_script_sha = None

    mock_pipeline = MagicMock()
    mock_pipeline.zadd = MagicMock()
    mock_pipeline.zremrangebyscore = MagicMock()
    mock_pipeline.zcard = MagicMock()
    mock_pipeline.zrange = MagicMock()
    mock_pipeline.expire = MagicMock()
    mock_pipeline.execute = AsyncMock(side_effect=[[0, 3, []], [1, True]])

    mock_conn = MagicMock()
    mock_conn.time = AsyncMock(return_value=(1000, 500000))
    mock_conn.pipeline = MagicMock(return_value=mock_pipeline)

    @asynccontextmanager
    async def mock_get_connection() -> AsyncGenerator[MagicMock, None]:
        yield mock_conn

    redis = MagicMock()
    redis.get_connection = mock_get_connection
    redis.config = MagicMock()
    redis.config.redis_prefix = "test:"
    mgr.redis_handler = redis

    verdict = await _global_verdict(mgr)
    assert verdict == RateLimitVerdict(None)
    mock_pipeline.zadd.assert_called_once_with(
        "test:rate_limit:rate:1.2.3.4", {"1000.5": 1000.5}
    )


def _fallback_redis(zrange_result: list[Any]) -> tuple[MagicMock, MagicMock]:
    mock_pipeline = MagicMock()
    mock_pipeline.execute = AsyncMock(
        side_effect=[[0, 2, zrange_result], [1, True, 1, True]]
    )
    mock_conn = MagicMock()
    mock_conn.time = AsyncMock(return_value=(1000, 0))
    mock_conn.pipeline = MagicMock(return_value=mock_pipeline)

    @asynccontextmanager
    async def mock_get_connection() -> AsyncGenerator[MagicMock, None]:
        yield mock_conn

    redis = MagicMock()
    redis.get_connection = mock_get_connection
    redis.config = MagicMock()
    redis.config.redis_prefix = "test:"
    return redis, mock_pipeline


async def test_ratelimit_fallback_blocks_with_the_oldest_hits_remaining_time() -> None:
    config = SecurityConfig(enable_redis=True, redis_url="redis://localhost:6379")
    mgr = RateLimitManager(config)
    mgr.rate_limit_script_sha = None
    mgr.redis_handler, pipeline = _fallback_redis([("990.0", 990.0)])

    verdict = await mgr._tier_verdict(
        "1.2.3.4", [RateLimitTier("global", 2, 60)], config
    )

    assert verdict == RateLimitVerdict(0, 3, 50)
    assert pipeline.execute.await_count == 1


async def test_ratelimit_fallback_blocks_with_the_full_window_when_it_is_empty() -> (
    None
):
    config = SecurityConfig(enable_redis=True, redis_url="redis://localhost:6379")
    mgr = RateLimitManager(config)
    mgr.rate_limit_script_sha = None
    mgr.redis_handler, _ = _fallback_redis([])

    verdict = await mgr._tier_verdict(
        "1.2.3.4", [RateLimitTier("global", 2, 60)], config
    )

    assert verdict == RateLimitVerdict(0, 3, 60)


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
        await _global_verdict(mgr)


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

    assert await _global_verdict(mgr) == RateLimitVerdict(None)
    assert mgr.request_timestamps


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
        await _global_verdict(mgr)


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

    assert await _global_verdict(mgr) == RateLimitVerdict(None)
    assert mgr.request_timestamps


async def test_ratelimit_in_memory_with_endpoint() -> None:
    config = SecurityConfig(enable_redis=False)
    mgr = RateLimitManager(config)
    verdict = _in_memory_tier_verdict(
        mgr.request_timestamps,
        "1.2.3.4",
        [RateLimitTier("endpoint", 10, 60, "/api")],
        time.time(),
    )
    assert verdict == RateLimitVerdict(None)
    assert len(mgr.request_timestamps) == 1


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
    mock_conn.evalsha = AsyncMock(return_value=[1, 5, 20])

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
    mock_conn.evalsha = AsyncMock(return_value=[0, 0, 0])

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
    redis.delete_pattern = AsyncMock()
    mgr.redis_handler = redis
    await mgr.reset()
    patterns = [call.args[0] for call in redis.delete_pattern.call_args_list]
    assert patterns == ["rate_limit:rate:*", "rate_limit:violations:*"]


async def test_ratelimit_reset_redis_exception() -> None:
    config = SecurityConfig(enable_redis=True, redis_url="redis://localhost:6379")
    mgr = RateLimitManager(config)
    redis = MagicMock()
    redis.delete_pattern = AsyncMock(side_effect=Exception("fail"))
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
    mock_conn.evalsha = AsyncMock(return_value=[0, 0, 0])

    @asynccontextmanager
    async def mock_get_connection() -> AsyncGenerator[MagicMock, None]:
        yield mock_conn

    redis = MagicMock()
    redis.get_connection = mock_get_connection
    redis.config = MagicMock()
    redis.config.redis_prefix = "test:"
    mgr.redis_handler = redis

    verdict = await mgr._tier_verdict(
        "1.2.3.4", [RateLimitTier("endpoint", 10, 60, "/api")], config
    )
    assert verdict == RateLimitVerdict(None)
    key = mock_conn.evalsha.await_args.args[2]
    assert key.startswith("test:rate_limit:rate:1.2.3.4:endpoint:")


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
