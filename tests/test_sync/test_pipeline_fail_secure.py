from types import SimpleNamespace
from unittest.mock import MagicMock

from redis.exceptions import RedisError

from guard_core.exceptions import GuardRedisError
from guard_core.models import SyncSecurityConfig
from guard_core.sync.core.checks.implementations.rate_limit import RateLimitCheck
from guard_core.sync.core.checks.pipeline import SecurityCheckPipeline
from guard_core.sync.handlers.ratelimit_handler import RateLimitManager
from tests.test_sync.conftest import SyncMockGuardRequest


def _redis_failing_check(config: SyncSecurityConfig) -> MagicMock:
    check = MagicMock()
    check.check_name = "ip_security"
    check.config = config
    check.check = MagicMock(side_effect=GuardRedisError(503, "Redis connection failed"))
    check.create_error_response = MagicMock(
        return_value=SimpleNamespace(status_code=503, headers={})
    )
    return check


class _FailingConnection:
    def __enter__(self) -> None:
        raise RedisError("down")

    def __exit__(self, *_args: object) -> None:
        return None


def _rate_limit_check_with_broken_redis(config: SyncSecurityConfig) -> RateLimitCheck:
    rate_limit_manager = RateLimitManager(config)
    rate_limit_manager.rate_limit_script_sha = "sha123"
    redis = MagicMock()
    redis.get_connection = lambda: _FailingConnection()
    redis.config = MagicMock(redis_prefix="test:")
    rate_limit_manager.redis_handler = redis

    middleware = MagicMock()
    middleware.config = config
    middleware.logger = MagicMock()
    middleware.route_resolver.should_bypass_check = MagicMock(return_value=False)
    middleware.rate_limit_handler = rate_limit_manager
    middleware.create_error_response = MagicMock(
        side_effect=lambda code, _message: SimpleNamespace(status_code=code, headers={})
    )
    return RateLimitCheck(middleware)


def _rate_limit_request() -> SyncMockGuardRequest:
    request = SyncMockGuardRequest(path="/x")
    request.state.is_whitelisted = False
    request.state.client_ip = "203.0.113.20"
    request.state.route_config = None
    return request


def test_default_security_config_is_fail_secure() -> None:
    config = SyncSecurityConfig()
    assert hasattr(config, "fail_secure")
    assert config.fail_secure is True


def test_fail_secure_can_be_disabled() -> None:
    config = SyncSecurityConfig(fail_secure=False)
    assert config.fail_secure is False


def test_pipeline_returns_blocked_when_fail_secure_and_check_raises() -> None:
    middleware = MagicMock()
    middleware.config = SyncSecurityConfig(fail_secure=True)
    middleware.logger = MagicMock()

    failing_check = MagicMock()
    failing_check.check_name = "boom"
    failing_check.config = middleware.config
    failing_check.is_muted = False
    failing_check.check = MagicMock(side_effect=RuntimeError("boom"))
    blocked = SimpleNamespace(status_code=500, headers={})
    failing_check.create_error_response = MagicMock(return_value=blocked)

    pipeline = SecurityCheckPipeline([failing_check])
    result = pipeline.execute(MagicMock())
    assert result is blocked
    assert "Retry-After" not in blocked.headers
    failing_check.create_error_response.assert_called_once_with(
        status_code=500, default_message="Security check failed"
    )


def test_pipeline_falls_through_when_not_fail_secure() -> None:
    middleware = MagicMock()
    middleware.config = SyncSecurityConfig(fail_secure=False)
    middleware.logger = MagicMock()

    failing_check = MagicMock()
    failing_check.check_name = "boom"
    failing_check.config = middleware.config
    failing_check.is_muted = False
    failing_check.check = MagicMock(side_effect=RuntimeError("boom"))

    pipeline = SecurityCheckPipeline([failing_check])
    result = pipeline.execute(MagicMock())
    assert result is None


def test_default_security_config_is_not_redis_fail_open() -> None:
    config = SyncSecurityConfig()
    assert config.redis_fail_open is False


def test_pipeline_blocks_on_redis_error_with_default_config() -> None:
    """fail_secure is the single source of truth by default: a Redis error
    blocks the request unless redis_fail_open is explicitly opted into."""
    failing_check = _redis_failing_check(SyncSecurityConfig(fail_secure=True))

    pipeline = SecurityCheckPipeline([failing_check])
    result = pipeline.execute(MagicMock())

    assert result is failing_check.create_error_response.return_value
    assert result.headers["Retry-After"] == "5"


def test_pipeline_fails_open_on_redis_error_despite_fail_secure() -> None:
    failing_check = _redis_failing_check(
        SyncSecurityConfig(fail_secure=True, redis_fail_open=True)
    )

    pipeline = SecurityCheckPipeline([failing_check])
    result = pipeline.execute(MagicMock())

    assert result is None
    failing_check.create_error_response.assert_not_called()


def test_pipeline_fails_open_on_redis_error_without_logging_when_muted() -> None:
    """Fail-open still happens for a muted check, but the skip is not logged."""
    failing_check = _redis_failing_check(
        SyncSecurityConfig(fail_secure=True, redis_fail_open=True)
    )

    pipeline = SecurityCheckPipeline(
        [failing_check], muted_check_logs=frozenset({"ip_security"})
    )
    logger = MagicMock()
    pipeline.logger = logger

    result = pipeline.execute(MagicMock())

    assert result is None
    failing_check.create_error_response.assert_not_called()
    logger.warning.assert_not_called()


def test_pipeline_blocks_on_redis_error_when_fail_open_disabled() -> None:
    failing_check = _redis_failing_check(
        SyncSecurityConfig(fail_secure=True, redis_fail_open=False)
    )

    pipeline = SecurityCheckPipeline([failing_check])
    result = pipeline.execute(MagicMock())

    assert result is failing_check.create_error_response.return_value
    assert result.headers["Retry-After"] == "5"


def test_pipeline_rate_limit_check_blocks_when_fail_secure() -> None:
    config = SyncSecurityConfig(
        enable_redis=True,
        enable_rate_limiting=True,
        rate_limit=100,
        fail_secure=True,
        redis_fail_open=False,
    )
    check = _rate_limit_check_with_broken_redis(config)

    pipeline = SecurityCheckPipeline([check])
    result = pipeline.execute(_rate_limit_request())

    assert result is not None
    assert result.status_code == 503
    assert result.headers["Retry-After"] == "5"


def test_pipeline_rate_limit_check_passes_through_when_not_fail_secure() -> None:
    config = SyncSecurityConfig(
        enable_redis=True,
        enable_rate_limiting=True,
        rate_limit=100,
        fail_secure=False,
        redis_fail_open=False,
    )
    check = _rate_limit_check_with_broken_redis(config)

    pipeline = SecurityCheckPipeline([check])
    result = pipeline.execute(_rate_limit_request())

    assert result is None
