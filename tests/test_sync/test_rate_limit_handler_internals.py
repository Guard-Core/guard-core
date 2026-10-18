import logging
from collections import defaultdict, deque
from typing import Any
from unittest.mock import MagicMock, Mock, patch

import pytest
from redis.exceptions import NoScriptError, RedisError

from guard_core.exceptions import GuardRedisError
from guard_core.models import SecurityConfig
from guard_core.sync.handlers import ratelimit_handler
from guard_core.sync.handlers.ipban_handler import IPBanManager
from guard_core.sync.handlers.ratelimit_handler import (
    RateLimitManager,
    RateLimitTier,
    RateLimitVerdict,
    _evalsha_tiers,
    _in_memory_tier_verdict,
    _pipeline_tiers_verdict,
    _redis_tier_verdict,
    _resolve_redis_rate_limit_failure,
    _shared_primitive_counts,
    _warn_redis_fail_open_in_memory_fallback,
    check_rate_limit_by_ip,
)
from tests.test_sync.conftest import MockGuardResponse, SyncMockGuardRequest

IP = "198.51.100.50"
HANDLER_LOGGER = "guard_core.sync.handlers.ratelimit"


def _error_response(status_code: int, message: str) -> MockGuardResponse:
    return MockGuardResponse(message, status_code)


def _request() -> SyncMockGuardRequest:
    return SyncMockGuardRequest(path="/x", client_host=IP)


def _config(**settings: Any) -> SecurityConfig:
    return SecurityConfig(**{"enable_redis": False, **settings})


class _Connection:
    def __init__(self, handler: "_RedisHandler") -> None:
        self.handler = handler

    def __enter__(self) -> Any:
        if self.handler.connect_error is not None:
            raise self.handler.connect_error
        return self.handler.conn

    def __exit__(self, *exc_info: object) -> None:
        return None


class _RedisHandler:
    def __init__(self, conn: Any = None, connect_error: Exception | None = None):
        self.config = SecurityConfig(enable_redis=True, redis_prefix="p:")
        self.conn = conn
        self.connect_error = connect_error

    def get_connection(self) -> _Connection:
        return _Connection(self)


class _Pipeline:
    def __init__(self, results: list[Any]) -> None:
        self.calls: list[tuple[str, tuple[Any, ...], dict[str, Any]]] = []
        self.results = results

    def zremrangebyscore(self, *args: Any, **kwargs: Any) -> None:
        self.calls.append(("zremrangebyscore", args, kwargs))

    def zcard(self, *args: Any, **kwargs: Any) -> None:
        self.calls.append(("zcard", args, kwargs))

    def zrange(self, *args: Any, **kwargs: Any) -> None:
        self.calls.append(("zrange", args, kwargs))

    def zadd(self, *args: Any, **kwargs: Any) -> None:
        self.calls.append(("zadd", args, kwargs))

    def expire(self, *args: Any, **kwargs: Any) -> None:
        self.calls.append(("expire", args, kwargs))

    def execute(self) -> list[Any]:
        return self.results


class _PipelineConnection:
    def __init__(self, inspect_results: list[Any]) -> None:
        self.inspect = _Pipeline(inspect_results)
        self.record = _Pipeline([])
        self.pipelines = [self.inspect, self.record]

    def time(self) -> tuple[int, int]:
        return (1000, 500_000)

    def pipeline(self) -> _Pipeline:
        return self.pipelines.pop(0)


def test_the_handler_loggers_carry_the_documented_name() -> None:
    assert ratelimit_handler._by_ip_logger.name == HANDLER_LOGGER
    assert RateLimitManager(_config()).logger.name == HANDLER_LOGGER


def test_a_verdict_defaults_to_no_count_and_no_retry_after() -> None:
    assert RateLimitVerdict(None) == (None, 0, 0)


def test_a_new_manager_holds_no_handlers_and_no_script() -> None:
    manager = RateLimitManager(_config())

    assert manager.redis_handler is None
    assert manager.agent_handler is None
    assert manager.rate_limit_script_sha is None
    assert RateLimitManager.redis_handler is None
    assert RateLimitManager.agent_handler is None
    assert RateLimitManager.rate_limit_script_sha is None


def test_the_fail_open_warning_names_the_effective_limit(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setattr(ratelimit_handler, "_redis_fail_open_warned", False)

    with caplog.at_level(logging.WARNING, logger=HANDLER_LOGGER):
        _warn_redis_fail_open_in_memory_fallback()
        _warn_redis_fail_open_in_memory_fallback()

    (record,) = caplog.records
    assert record.getMessage() == (
        "Redis unavailable for rate limiting; using the in-memory window "
        "(redis_fail_open=True); with several workers the effective limit "
        "is workers x rate_limit"
    )


def test_a_closed_failure_logs_the_cause_and_raises_a_503() -> None:
    logger = Mock()
    cause = RedisError("boom")

    with pytest.raises(GuardRedisError) as raised:
        _resolve_redis_rate_limit_failure(cause, False, logger, "the context")

    assert raised.value.status_code == 503
    assert raised.value.detail == "Redis rate limiting unavailable"
    logger.error.assert_called_once_with("the context: boom")


def test_a_redis_error_is_logged_with_its_context_and_raises() -> None:
    logger = Mock()
    handler = _RedisHandler(connect_error=RedisError("down"))

    with pytest.raises(GuardRedisError):
        _redis_tier_verdict(
            handler, logger, IP, [RateLimitTier("global", 1, 60)], None, None, False
        )

    logger.error.assert_called_once_with("Redis rate limiting error: down")


def test_an_unexpected_error_is_logged_with_its_context_and_raises() -> None:
    logger = Mock()
    handler = _RedisHandler(connect_error=ValueError("odd"))

    with pytest.raises(GuardRedisError):
        _redis_tier_verdict(
            handler, logger, IP, [RateLimitTier("global", 1, 60)], None, None, False
        )

    logger.error.assert_called_once_with("Unexpected error in rate limiting: odd")


def test_redis_failures_raise_unless_fail_open_is_asked_for() -> None:
    handler = _RedisHandler(connect_error=RedisError("down"))
    tiers = [RateLimitTier("global", 1, 60)]

    with pytest.raises(GuardRedisError):
        _redis_tier_verdict(handler, Mock(), IP, tiers, None)


def test_a_noscript_reply_reloads_the_script_and_logs_it() -> None:
    logger = Mock()
    conn = MagicMock()
    conn.evalsha = MagicMock(side_effect=[NoScriptError("gone"), [0, 0, 0]])
    conn.script_load = MagicMock(return_value="sha2")

    result, sha = _evalsha_tiers(
        conn, logger, "sha1", ["k"], [RateLimitTier("global", 1, 60)], None
    )

    assert (list(result), sha) == ([0, 0, 0], "sha2")
    logger.info.assert_called_once_with("Rate limit Lua script reloaded after NOSCRIPT")


def test_the_fallback_pipeline_reads_every_tier_and_records_with_a_ttl() -> None:
    conn = _PipelineConnection([0, 1, [], 0, 0, []])
    tiers = [RateLimitTier("global", 5, 60), RateLimitTier("route", 5, 30, "r")]

    verdict = _pipeline_tiers_verdict(conn, ["k1", "k2"], tiers)

    assert verdict == (None, 0, 0)
    now = 1000.5
    assert conn.inspect.calls == [
        ("zremrangebyscore", ("k1", 0, now - 60), {}),
        ("zcard", ("k1",), {}),
        ("zrange", ("k1", 0, 0), {"withscores": True}),
        ("zremrangebyscore", ("k2", 0, now - 30), {}),
        ("zcard", ("k2",), {}),
        ("zrange", ("k2", 0, 0), {"withscores": True}),
    ]
    assert conn.record.calls == [
        ("zadd", ("k1", {str(now): now}), {}),
        ("expire", ("k1", 120), {}),
        ("zadd", ("k2", {str(now): now}), {}),
        ("expire", ("k2", 60), {}),
    ]


def test_the_fallback_pipeline_blocks_on_the_second_tier() -> None:
    conn = _PipelineConnection([0, 1, [], 0, 3, [("m", 990.5)]])
    tiers = [RateLimitTier("global", 5, 60), RateLimitTier("route", 3, 30, "r")]

    verdict = _pipeline_tiers_verdict(conn, ["k1", "k2"], tiers)

    assert verdict == (1, 4, 20)
    assert conn.record.calls == []


def test_a_hit_exactly_one_window_old_has_left_the_window() -> None:
    tier = RateLimitTier("global", 1, 60)
    store: defaultdict[str, deque[float]] = defaultdict(deque)
    store[IP].append(100.0)

    verdict = _in_memory_tier_verdict(store, IP, [tier], 160.0)

    assert verdict.tier_index is None
    assert list(store[IP]) == [160.0]


def test_the_shared_counter_needs_redis_enabled_and_a_handler(
    caplog: pytest.LogCaptureFixture,
) -> None:
    handler = Mock()

    with caplog.at_level(logging.WARNING, logger=HANDLER_LOGGER):
        assert _shared_primitive_counts(IP, _config(enable_redis=True), None) is None
        assert _shared_primitive_counts(IP, _config(), handler) is None

    assert caplog.records == []


def test_the_fail_open_warning_flag_starts_unset() -> None:
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "fresh_ratelimit_handler", ratelimit_handler.__file__
    )
    assert spec is not None and spec.loader is not None
    fresh = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fresh)

    assert fresh._redis_fail_open_warned is False


def test_an_unavailable_shared_counter_is_logged_by_the_primitive(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = _config(enable_redis=True, redis_url="redis://localhost:1")

    with (
        caplog.at_level(logging.WARNING, logger=HANDLER_LOGGER),
        patch.object(
            ratelimit_handler,
            "record_shared_violation",
            MagicMock(side_effect=RuntimeError("redis down")),
        ),
    ):
        assert _shared_primitive_counts(IP, config, Mock()) is None

    (record,) = caplog.records
    assert record.getMessage() == (
        "Shared rate-limit violation counter unavailable, counting this "
        "violation in this process only: redis down"
    )


def test_a_landed_primitive_ban_is_logged(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = _config(
        rate_limit=1,
        rate_limit_window=60,
        enable_rate_limit_auto_ban=True,
        enable_ip_banning=True,
        auto_ban_threshold=1,
    )
    IPBanManager._instance = None
    manager = IPBanManager()
    manager.redis_handler = None
    manager.config = config
    ratelimit_handler._by_ip_autoban_counts.clear()
    try:
        with (
            caplog.at_level(logging.WARNING, logger=HANDLER_LOGGER),
            patch.object(manager, "ban_ip", MagicMock(return_value=True)),
        ):
            check_rate_limit_by_ip("192.0.2.77", config)
            check_rate_limit_by_ip("192.0.2.77", config)
    finally:
        IPBanManager._instance = None

    assert "check_rate_limit_by_ip: auto-banned 192.0.2.77 (rate_limit_exceeded)" in [
        record.getMessage() for record in caplog.records
    ]


def test_the_primitive_event_names_the_endpoint_and_leaves_global_blank() -> None:
    config = _config(rate_limit=1, rate_limit_window=60)
    agent = Mock()
    agent.send_event = MagicMock()

    for path in ("", "ws"):
        for _ in range(2):
            check_rate_limit_by_ip(
                "192.0.2.78", config, endpoint_path=path, agent_handler=agent
            )

    sent = [call.args[0] for call in agent.send_event.call_args_list]
    assert [event.endpoint for event in sent] == [None, "ws"]
    assert {event.handler_name for event in sent} == {"rate_limit"}


def test_a_failing_agent_does_not_fail_the_primitive(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = _config(rate_limit=1, rate_limit_window=60)
    agent = Mock()
    agent.send_event = MagicMock(side_effect=RuntimeError("boom"))

    with caplog.at_level(logging.ERROR, logger=HANDLER_LOGGER):
        check_rate_limit_by_ip("192.0.2.79", config, agent_handler=agent)
        allowed = check_rate_limit_by_ip("192.0.2.79", config, agent_handler=agent)

    assert allowed is False
    assert [r.getMessage() for r in caplog.records] == [
        "Failed to send rate limit event to agent: boom"
    ]


def test_the_primitive_rejects_bad_input_with_a_readable_message() -> None:
    config = _config()

    with pytest.raises(ValueError) as bad_ip:
        check_rate_limit_by_ip("not-an-ip", config)
    with pytest.raises(ValueError) as bad_path:
        check_rate_limit_by_ip("192.0.2.80", config, endpoint_path="a:b")

    assert str(bad_ip.value) == "check_rate_limit_by_ip: invalid ip 'not-an-ip'"
    assert str(bad_path.value) == (
        "check_rate_limit_by_ip: endpoint_path must not contain ':' (got 'a:b')"
    )


def test_the_script_load_is_logged_on_both_outcomes(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = _config(enable_redis=True, redis_url="redis://localhost:1")
    manager = RateLimitManager(config)
    ok = _RedisHandler(conn=MagicMock())
    ok.conn.script_load = MagicMock(return_value="sha")
    broken = _RedisHandler(connect_error=RuntimeError("no redis"))

    with caplog.at_level(logging.INFO, logger=HANDLER_LOGGER):
        manager.initialize_redis(ok)
        manager.initialize_redis(broken)

    assert [r.getMessage() for r in caplog.records] == [
        "Rate limiting Lua script loaded successfully",
        "Failed to load rate limiting Lua script: no redis",
    ]


def test_the_reload_event_is_a_system_event_and_a_failing_send_is_logged(
    caplog: pytest.LogCaptureFixture,
) -> None:
    manager = RateLimitManager(_config())
    agent = Mock()
    agent.send_event = MagicMock()
    manager.initialize_agent(agent)

    manager._emit_script_reloaded_event()

    (event,) = [call.args[0] for call in agent.send_event.call_args_list]
    assert event.ip_address == "system"
    assert event.action_taken == "script_reloaded"
    assert event.reason == "NOSCRIPT recovery: Lua script re-cached on Redis"
    assert event.handler_name == "rate_limit"

    agent.send_event = MagicMock(side_effect=RuntimeError("boom"))
    with caplog.at_level(logging.ERROR, logger=HANDLER_LOGGER):
        manager._emit_script_reloaded_event()
    assert [r.getMessage() for r in caplog.records] == [
        "Failed to send script-reload event: boom"
    ]


def test_a_block_is_logged_with_count_and_window_and_defaults_to_config() -> None:
    config = _config(rate_limit_window=77)
    manager = RateLimitManager(config)

    with patch.object(ratelimit_handler, "log_activity", MagicMock()) as logged:
        response = manager._handle_rate_limit_exceeded(
            _request(), IP, 7, _error_response
        )
        explicit = manager._handle_rate_limit_exceeded(
            _request(), IP, 7, _error_response, rate_limit_window=30
        )

    assert response.headers["Retry-After"] == "77"
    assert explicit.headers["Retry-After"] == "30"
    first, second = logged.call_args_list
    assert first.kwargs["reason"] == (
        f"Rate limit exceeded for IP: {IP} (7 requests in 77s window)"
    )
    assert second.kwargs["reason"] == (
        f"Rate limit exceeded for IP: {IP} (7 requests in 30s window)"
    )
    assert first.kwargs["log_type"] == "suspicious"
    assert first.kwargs["check_name"] == "rate_limit"


def test_a_config_passed_to_the_check_wins_over_the_manager_config() -> None:
    manager = RateLimitManager(_config(log_suspicious_level="INFO"))
    passed = _config(log_suspicious_level="ERROR")
    tier = RateLimitTier("global", 1, 60)

    with patch.object(ratelimit_handler, "log_activity", MagicMock()) as logged:
        for _ in range(2):
            block = manager.check_rate_limit_tiers(
                _request(), IP, _error_response, [tier], passed
            )

    assert block is not None
    assert logged.call_args_list[-1].kwargs["level"] == "ERROR"


def test_an_endpoint_check_keeps_its_window_apart_from_the_global_key() -> None:
    manager = RateLimitManager(_config(rate_limit=5, rate_limit_window=60))

    manager.check_rate_limit(
        _request(), IP, _error_response, endpoint_path="/x", rate_limit=1
    )

    (key,) = list(manager.request_timestamps)
    assert key.startswith(f"{IP}:endpoint:")


def test_a_failing_agent_does_not_fail_the_rate_limit_event(
    caplog: pytest.LogCaptureFixture,
) -> None:
    manager = RateLimitManager(_config())
    agent = Mock()
    agent.send_event = MagicMock(side_effect=RuntimeError("boom"))
    manager.initialize_agent(agent)

    with caplog.at_level(logging.ERROR, logger=HANDLER_LOGGER):
        manager._send_rate_limit_event(_request(), IP, 3)

    assert [r.getMessage() for r in caplog.records] == [
        "Failed to send rate limit event to agent: boom"
    ]


def test_reset_clears_redis_only_when_redis_is_enabled_and_has_keys() -> None:
    enabled = _config(enable_redis=True, redis_url="redis://localhost:1")
    redis = Mock()
    redis.keys = MagicMock(return_value=["rate_limit:rate:a"])
    redis.delete_pattern = MagicMock()
    manager = RateLimitManager(enabled)
    manager.redis_handler = redis
    manager.agent_handler = Mock()

    manager.reset()

    redis.keys.assert_called_once_with("rate_limit:rate:*")
    redis.delete_pattern.assert_called_once_with("rate_limit:rate:*")
    assert manager.redis_handler is None
    assert manager.agent_handler is None


def test_reset_leaves_redis_alone_when_it_is_disabled_or_empty() -> None:
    redis = Mock()
    redis.keys = MagicMock(return_value=[])
    redis.delete_pattern = MagicMock()
    disabled = RateLimitManager(_config())
    disabled.redis_handler = redis
    disabled.reset()
    redis.keys.assert_not_called()

    empty = RateLimitManager(_config(enable_redis=True, redis_url="redis://x:1"))
    empty.redis_handler = redis
    empty.reset()
    redis.keys.assert_called_once()
    redis.delete_pattern.assert_not_called()


def test_reset_without_a_redis_handler_logs_nothing(
    caplog: pytest.LogCaptureFixture,
) -> None:
    manager = RateLimitManager(_config(enable_redis=True, redis_url="redis://x:1"))

    with caplog.at_level(logging.ERROR, logger=HANDLER_LOGGER):
        manager.reset()

    assert caplog.records == []


def test_reset_tolerates_a_keys_reply_of_none_and_logs_a_failure(
    caplog: pytest.LogCaptureFixture,
) -> None:
    redis = Mock()
    redis.keys = MagicMock(return_value=None)
    redis.delete_pattern = MagicMock()
    manager = RateLimitManager(_config(enable_redis=True, redis_url="redis://x:1"))
    manager.redis_handler = redis

    with caplog.at_level(logging.ERROR, logger=HANDLER_LOGGER):
        manager.reset()
    assert caplog.records == []
    redis.delete_pattern.assert_not_called()

    redis.keys = MagicMock(side_effect=RuntimeError("boom"))
    manager.redis_handler = redis
    with caplog.at_level(logging.ERROR, logger=HANDLER_LOGGER):
        manager.reset()
    assert [r.getMessage() for r in caplog.records] == [
        "Failed to reset Redis rate limits: boom"
    ]
