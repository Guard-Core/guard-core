import logging
import time
from unittest.mock import MagicMock

import pytest
from redis.exceptions import NoScriptError, RedisError

from guard_core.exceptions import GuardRedisError
from guard_core.models import SecurityConfig
from guard_core.sync.handlers.ratelimit_handler import (
    RateLimitManager,
    RateLimitTier,
    RateLimitVerdict,
    _by_ip_request_timestamps,
    _redis_tier_verdict,
    check_rate_limit_by_ip,
)
from guard_core.sync.handlers.redis_handler import redis_handler


class _FailingConnection:
    def __init__(self, exc: BaseException) -> None:
        self._exc = exc

    def __enter__(self) -> None:
        raise self._exc

    def __exit__(self, *_args: object) -> None:
        return None


def _broken_redis_handler() -> MagicMock:
    redis = MagicMock()
    redis.config = MagicMock(redis_prefix="test:")
    redis.get_connection = lambda: _FailingConnection(RedisError("down"))
    return redis


def test_under_limit_stays_allowed() -> None:
    config = SecurityConfig(enable_redis=False, rate_limit=2, rate_limit_window=60)

    assert check_rate_limit_by_ip("203.0.113.1", config) is True
    assert check_rate_limit_by_ip("203.0.113.1", config) is True


def test_over_limit_becomes_blocked() -> None:
    config = SecurityConfig(enable_redis=False, rate_limit=1, rate_limit_window=60)

    assert check_rate_limit_by_ip("203.0.113.2", config) is True
    assert check_rate_limit_by_ip("203.0.113.2", config) is False


def test_window_expiry_recovers_after_block() -> None:
    config = SecurityConfig(enable_redis=False, rate_limit=1, rate_limit_window=1)

    assert check_rate_limit_by_ip("203.0.113.3", config) is True
    assert check_rate_limit_by_ip("203.0.113.3", config) is False

    time.sleep(1.1)

    assert check_rate_limit_by_ip("203.0.113.3", config) is True


def test_redis_path_enforces_limit(
    security_config_redis: SecurityConfig,
) -> None:
    security_config_redis.rate_limit = 2
    security_config_redis.rate_limit_window = 60
    handler = redis_handler(security_config_redis)
    handler.initialize()
    try:
        ip = "203.0.113.4"
        assert (
            check_rate_limit_by_ip(
                ip, security_config_redis, redis_handler=handler, endpoint_path="ws"
            )
            is True
        )
        assert (
            check_rate_limit_by_ip(
                ip, security_config_redis, redis_handler=handler, endpoint_path="ws"
            )
            is True
        )
        assert (
            check_rate_limit_by_ip(
                ip, security_config_redis, redis_handler=handler, endpoint_path="ws"
            )
            is False
        )
    finally:
        handler.close()


def test_falls_back_to_in_memory_when_redis_handler_not_supplied() -> None:
    config = SecurityConfig(enable_redis=True, rate_limit=1, rate_limit_window=60)

    ip = "203.0.113.5"
    assert check_rate_limit_by_ip(ip, config) is True
    assert check_rate_limit_by_ip(ip, config) is False


def test_redis_error_raises_when_fail_open_is_false() -> None:
    config = SecurityConfig(enable_redis=True, rate_limit=1, rate_limit_window=60)
    redis = _broken_redis_handler()

    ip = "203.0.113.6"
    with pytest.raises(GuardRedisError):
        check_rate_limit_by_ip(ip, config, redis_handler=redis)


def test_redis_error_falls_back_to_in_memory_count_when_fail_open_is_true() -> None:
    config = SecurityConfig(
        enable_redis=True, rate_limit=1, rate_limit_window=60, redis_fail_open=True
    )
    redis = _broken_redis_handler()

    ip = "203.0.113.106"
    assert check_rate_limit_by_ip(ip, config, redis_handler=redis) is True
    assert check_rate_limit_by_ip(ip, config, redis_handler=redis) is False


def _pipeline_hit(pipeline: RateLimitManager, ip: str, endpoint_path: str = "") -> bool:
    tier = RateLimitTier(
        "", pipeline.config.rate_limit, pipeline.config.rate_limit_window, endpoint_path
    )
    verdict = pipeline._tier_verdict(ip, [tier], pipeline.config)
    return verdict.tier_index is None


def test_no_singleton_mutation_regression() -> None:
    config_a = SecurityConfig(enable_redis=False, rate_limit=5, rate_limit_window=60)
    pipeline_manager = RateLimitManager(config_a)

    config_b = SecurityConfig(enable_redis=False, rate_limit=1, rate_limit_window=60)
    check_rate_limit_by_ip("203.0.113.7", config_b)

    assert pipeline_manager.config is config_a
    assert not pipeline_manager.request_timestamps


def test_endpoint_path_namespacing_isolates_budgets() -> None:
    config = SecurityConfig(enable_redis=False, rate_limit=1, rate_limit_window=60)
    ip = "203.0.113.8"

    assert check_rate_limit_by_ip(ip, config, endpoint_path="a") is True
    assert check_rate_limit_by_ip(ip, config, endpoint_path="a") is False
    assert check_rate_limit_by_ip(ip, config, endpoint_path="b") is True


def test_default_endpoint_path_shares_pipeline_bucket_bidirectionally(
    security_config_redis: SecurityConfig,
) -> None:
    security_config_redis.rate_limit = 3
    security_config_redis.rate_limit_window = 60
    handler = redis_handler(security_config_redis)
    handler.initialize()
    try:
        ip = "203.0.113.9"
        pipeline = RateLimitManager(security_config_redis)
        pipeline.redis_handler = handler

        assert _pipeline_hit(pipeline, ip) is True
        assert check_rate_limit_by_ip(ip, security_config_redis, handler) is True
        assert _pipeline_hit(pipeline, ip) is True
        assert check_rate_limit_by_ip(ip, security_config_redis, handler) is False
    finally:
        handler.close()


def test_endpoint_path_ws_is_disjoint_from_pipeline_bucket(
    security_config_redis: SecurityConfig,
) -> None:
    security_config_redis.rate_limit = 3
    security_config_redis.rate_limit_window = 60
    handler = redis_handler(security_config_redis)
    handler.initialize()
    try:
        ip = "203.0.113.12"
        pipeline = RateLimitManager(security_config_redis)
        pipeline.redis_handler = handler

        assert _pipeline_hit(pipeline, ip) is True
        assert _pipeline_hit(pipeline, ip) is True

        for _ in range(3):
            assert (
                check_rate_limit_by_ip(
                    ip, security_config_redis, handler, endpoint_path="ws"
                )
                is True
            )
        assert (
            check_rate_limit_by_ip(
                ip, security_config_redis, handler, endpoint_path="ws"
            )
            is False
        )

        assert _pipeline_hit(pipeline, ip) is True
    finally:
        handler.close()


def test_enable_rate_limiting_false_returns_true() -> None:
    config = SecurityConfig(enable_rate_limiting=False)

    assert check_rate_limit_by_ip("203.0.113.10", config) is True


def test_redis_tier_verdict_reload_without_callback() -> None:
    conn = MagicMock()
    conn.evalsha = MagicMock(side_effect=[NoScriptError("NOSCRIPT"), [0, 0, 0]])
    conn.script_load = MagicMock(return_value="newsha")

    cm = MagicMock()
    cm.__enter__ = MagicMock(return_value=conn)
    cm.__exit__ = MagicMock(return_value=None)
    redis = MagicMock()
    redis.config = MagicMock(redis_prefix="test:")
    redis.get_connection = MagicMock(return_value=cm)

    verdict, new_sha = _redis_tier_verdict(
        redis,
        logging.getLogger("test.check_rate_limit_by_ip"),
        "203.0.113.11",
        [RateLimitTier("global", 10, 60)],
        "oldsha",
        None,
    )

    assert verdict == RateLimitVerdict(None)
    assert new_sha == "newsha"


def test_unparseable_ip_raises_value_error_ws_collision_string() -> None:
    config = SecurityConfig(enable_redis=False, rate_limit=5, rate_limit_window=60)

    try:
        check_rate_limit_by_ip("1.2.3.4:ws", config)
        raise AssertionError("expected ValueError")
    except ValueError:
        pass


def test_unparseable_ip_raises_value_error_empty_string() -> None:
    config = SecurityConfig(enable_redis=False, rate_limit=5, rate_limit_window=60)

    try:
        check_rate_limit_by_ip("", config)
        raise AssertionError("expected ValueError")
    except ValueError:
        pass


def test_unparseable_ip_raises_value_error_garbage_string() -> None:
    config = SecurityConfig(enable_redis=False, rate_limit=5, rate_limit_window=60)

    try:
        check_rate_limit_by_ip("not-an-ip", config)
        raise AssertionError("expected ValueError")
    except ValueError:
        pass


def test_colon_in_endpoint_path_raises_value_error() -> None:
    config = SecurityConfig(enable_redis=False, rate_limit=5, rate_limit_window=60)

    try:
        check_rate_limit_by_ip("203.0.113.20", config, endpoint_path="a:b")
        raise AssertionError("expected ValueError")
    except ValueError:
        pass


def test_colon_in_endpoint_path_error_message_is_redacted() -> None:
    config = SecurityConfig(enable_redis=False, rate_limit=5, rate_limit_window=60)
    secret = "password=hunter2topsecretvalue"

    try:
        check_rate_limit_by_ip("203.0.113.20", config, endpoint_path=f"a:{secret}")
        raise AssertionError("expected ValueError")
    except ValueError as exc:
        message = str(exc)
        assert "hunter2" not in message
        assert "[REDACTED]" in message


def test_redis_key_never_contains_endpoint_path_text(
    security_config_redis: SecurityConfig,
) -> None:
    security_config_redis.rate_limit = 5
    security_config_redis.rate_limit_window = 60
    handler = redis_handler(security_config_redis)
    handler.initialize()
    secret_path = "/orders/password=hunter2topsecretvalue"
    ip = "203.0.113.40"
    try:
        check_rate_limit_by_ip(
            ip, security_config_redis, redis_handler=handler, endpoint_path=secret_path
        )
        with handler.get_connection() as conn:
            keys = conn.keys(
                f"{security_config_redis.redis_prefix}rate_limit:rate:{ip}:*"
            )
        assert keys, "expected a rate-limit key for this ip"
        for raw_key in keys:
            key_text = raw_key.decode() if isinstance(raw_key, bytes) else raw_key
            assert secret_path not in key_text
            assert "hunter2topsecretvalue" not in key_text
    finally:
        handler.delete_pattern("*")
        handler.close()


def test_redis_equal_paths_share_a_key_different_paths_do_not(
    security_config_redis: SecurityConfig,
) -> None:
    security_config_redis.rate_limit = 100
    security_config_redis.rate_limit_window = 60
    handler = redis_handler(security_config_redis)
    handler.initialize()
    ip = "203.0.113.42"
    try:
        check_rate_limit_by_ip(
            ip, security_config_redis, redis_handler=handler, endpoint_path="/orders/1"
        )
        check_rate_limit_by_ip(
            ip, security_config_redis, redis_handler=handler, endpoint_path="/orders/1"
        )
        check_rate_limit_by_ip(
            ip, security_config_redis, redis_handler=handler, endpoint_path="/orders/2"
        )
        with handler.get_connection() as conn:
            keys = conn.keys(
                f"{security_config_redis.redis_prefix}rate_limit:rate:{ip}:*"
            )
        assert len(keys) == 2, keys
    finally:
        handler.delete_pattern("*")
        handler.close()


def test_in_memory_key_never_contains_endpoint_path_text() -> None:
    config = SecurityConfig(enable_redis=False, rate_limit=5, rate_limit_window=60)
    secret_path = "/orders/password=hunter2topsecretvalue"
    ip = "203.0.113.41"

    check_rate_limit_by_ip(ip, config, endpoint_path=secret_path)

    matching_keys = [
        key for key in _by_ip_request_timestamps if key.startswith(f"{ip}:")
    ]
    assert matching_keys, "expected an in-memory bucket for this ip"
    for key in matching_keys:
        assert secret_path not in key
        assert "hunter2topsecretvalue" not in key


def test_rejected_ip_records_no_hit_when_rate_limiting_enabled() -> None:
    config = SecurityConfig(enable_redis=False, rate_limit=1, rate_limit_window=60)

    try:
        check_rate_limit_by_ip("not-an-ip", config)
    except ValueError:
        pass

    assert check_rate_limit_by_ip("203.0.113.21", config) is True


def test_rejected_ip_records_no_hit_when_rate_limiting_disabled() -> None:
    disabled_config = SecurityConfig(enable_rate_limiting=False)

    try:
        check_rate_limit_by_ip("not-an-ip", disabled_config)
    except ValueError:
        pass

    enabled_config = SecurityConfig(
        enable_redis=False, rate_limit=1, rate_limit_window=60
    )
    assert check_rate_limit_by_ip("203.0.113.22", enabled_config) is True


def test_rejected_endpoint_path_records_no_hit() -> None:
    config = SecurityConfig(enable_redis=False, rate_limit=1, rate_limit_window=60)

    try:
        check_rate_limit_by_ip("203.0.113.23", config, endpoint_path="a:b")
    except ValueError:
        pass

    assert check_rate_limit_by_ip("203.0.113.23", config) is True


def test_valid_ipv4_accepted() -> None:
    config = SecurityConfig(enable_redis=False, rate_limit=5, rate_limit_window=60)

    assert check_rate_limit_by_ip("203.0.113.24", config) is True


def test_valid_ipv6_literal_accepted() -> None:
    config = SecurityConfig(enable_redis=False, rate_limit=5, rate_limit_window=60)

    assert check_rate_limit_by_ip("2001:db8::1", config) is True


def test_ipv6_shares_pipeline_bucket_bidirectionally(
    security_config_redis: SecurityConfig,
) -> None:
    security_config_redis.rate_limit = 3
    security_config_redis.rate_limit_window = 60
    handler = redis_handler(security_config_redis)
    handler.initialize()
    try:
        ip = "2001:db8::99"
        pipeline = RateLimitManager(security_config_redis)
        pipeline.redis_handler = handler

        assert _pipeline_hit(pipeline, ip) is True
        assert check_rate_limit_by_ip(ip, security_config_redis, handler) is True
        assert _pipeline_hit(pipeline, ip) is True
        assert check_rate_limit_by_ip(ip, security_config_redis, handler) is False
    finally:
        handler.close()


def test_primitive_raises_instead_of_colliding_with_pipeline_bucket(
    security_config_redis: SecurityConfig,
) -> None:
    security_config_redis.rate_limit = 2
    security_config_redis.rate_limit_window = 60
    handler = redis_handler(security_config_redis)
    handler.initialize()
    try:
        pipeline = RateLimitManager(security_config_redis)
        pipeline.redis_handler = handler

        assert _pipeline_hit(pipeline, "1.2.3.4", "ws") is True

        try:
            check_rate_limit_by_ip("1.2.3.4:ws", security_config_redis, handler)
            raise AssertionError("expected ValueError")
        except ValueError:
            pass

        assert _pipeline_hit(pipeline, "1.2.3.4", "ws") is True
        assert _pipeline_hit(pipeline, "1.2.3.4", "ws") is False
    finally:
        handler.close()


def test_in_memory_store_evicts_the_oldest_key_at_capacity() -> None:
    _by_ip_request_timestamps.clear()
    config = SecurityConfig(
        enable_redis=False,
        rate_limit=1000,
        rate_limit_window=60,
        rate_limit_max_tracked_keys=3,
    )

    for ip in ("10.0.0.1", "10.0.0.2", "10.0.0.3"):
        check_rate_limit_by_ip(ip, config)
    assert set(_by_ip_request_timestamps) == {"10.0.0.1", "10.0.0.2", "10.0.0.3"}

    check_rate_limit_by_ip("10.0.0.4", config)

    assert len(_by_ip_request_timestamps) == 3
    assert "10.0.0.1" not in _by_ip_request_timestamps
    assert "10.0.0.4" in _by_ip_request_timestamps


def test_in_memory_store_a_touched_key_survives_eviction() -> None:
    _by_ip_request_timestamps.clear()
    config = SecurityConfig(
        enable_redis=False,
        rate_limit=1000,
        rate_limit_window=60,
        rate_limit_max_tracked_keys=3,
    )

    for ip in ("10.0.1.1", "10.0.1.2", "10.0.1.3"):
        check_rate_limit_by_ip(ip, config)

    check_rate_limit_by_ip("10.0.1.1", config)
    check_rate_limit_by_ip("10.0.1.4", config)

    assert "10.0.1.1" in _by_ip_request_timestamps
    assert "10.0.1.2" not in _by_ip_request_timestamps
    assert len(_by_ip_request_timestamps) == 3
