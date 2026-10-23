from unittest.mock import MagicMock

import pytest
from redis.exceptions import NoScriptError, RedisError

from guard_core.exceptions import GuardRedisError
from guard_core.models import SyncSecurityConfig
from guard_core.sync.handlers import ratelimit_handler
from guard_core.sync.handlers.ratelimit_handler import (
    RateLimitManager,
    RateLimitTier,
    RateLimitVerdict,
)


@pytest.fixture(autouse=True)
def _reset_redis_fail_open_warning() -> None:
    ratelimit_handler._redis_fail_open_warned = False


@pytest.fixture
def manager() -> RateLimitManager:
    config = SyncSecurityConfig(enable_redis=True, rate_limit=100, rate_limit_window=60)
    mgr = RateLimitManager(config)
    mgr.rate_limit_script_sha = "deadbeef"
    return mgr


@pytest.fixture
def fail_open_manager() -> RateLimitManager:
    config = SyncSecurityConfig(
        enable_redis=True,
        rate_limit=100,
        rate_limit_window=60,
        redis_fail_open=True,
    )
    mgr = RateLimitManager(config)
    mgr.rate_limit_script_sha = "deadbeef"
    return mgr


def _verdict(manager: RateLimitManager) -> RateLimitVerdict:
    tiers = [RateLimitTier("global", 100, 60)]
    return manager._tier_verdict("1.1.1.1", tiers, manager.config)


def _make_redis_handler(conn: MagicMock) -> MagicMock:
    redis_handler = MagicMock()
    redis_handler.config = MagicMock(redis_prefix="test:")
    cm = MagicMock()
    cm.__enter__ = MagicMock(return_value=conn)
    cm.__exit__ = MagicMock(return_value=None)
    redis_handler.get_connection = MagicMock(return_value=cm)
    return redis_handler


def test_noscript_triggers_reload_and_retry_succeeds(
    manager: RateLimitManager,
) -> None:
    conn = MagicMock()
    conn.evalsha = MagicMock(side_effect=[NoScriptError("NOSCRIPT"), [0, 0, 0]])
    conn.script_load = MagicMock(return_value="newsha")
    manager.redis_handler = _make_redis_handler(conn)

    result = _verdict(manager)

    assert result == RateLimitVerdict(None)
    assert conn.script_load.call_count == 1
    assert conn.evalsha.call_count == 2
    assert manager.rate_limit_script_sha == "newsha"


def test_noscript_reload_failure_raises_when_fail_open_is_false(
    manager: RateLimitManager, caplog: pytest.LogCaptureFixture
) -> None:
    import logging

    conn = MagicMock()
    conn.evalsha = MagicMock(side_effect=NoScriptError("NOSCRIPT"))
    conn.script_load = MagicMock(side_effect=RedisError("connection lost"))
    manager.redis_handler = _make_redis_handler(conn)

    caplog.set_level(logging.ERROR)
    with pytest.raises(GuardRedisError):
        _verdict(manager)

    assert any("Redis rate limiting error" in r.message for r in caplog.records)


def test_noscript_reload_failure_falls_back_when_fail_open_is_true(
    fail_open_manager: RateLimitManager, caplog: pytest.LogCaptureFixture
) -> None:
    import logging

    conn = MagicMock()
    conn.evalsha = MagicMock(side_effect=NoScriptError("NOSCRIPT"))
    conn.script_load = MagicMock(side_effect=RedisError("connection lost"))
    fail_open_manager.redis_handler = _make_redis_handler(conn)

    caplog.set_level(logging.WARNING)
    result = _verdict(fail_open_manager)

    assert result == RateLimitVerdict(None)
    assert fail_open_manager.request_timestamps
    assert any(
        "Redis unavailable for rate limiting" in r.message for r in caplog.records
    )


def test_double_noscript_raises_when_fail_open_is_false(
    manager: RateLimitManager,
) -> None:
    conn = MagicMock()
    conn.evalsha = MagicMock(
        side_effect=[NoScriptError("first"), NoScriptError("second")]
    )
    conn.script_load = MagicMock(return_value="newsha")
    manager.redis_handler = _make_redis_handler(conn)

    with pytest.raises(GuardRedisError):
        _verdict(manager)


def test_double_noscript_falls_back_when_fail_open_is_true(
    fail_open_manager: RateLimitManager,
) -> None:
    conn = MagicMock()
    conn.evalsha = MagicMock(
        side_effect=[NoScriptError("first"), NoScriptError("second")]
    )
    conn.script_load = MagicMock(return_value="newsha")
    fail_open_manager.redis_handler = _make_redis_handler(conn)

    result = _verdict(fail_open_manager)

    assert result == RateLimitVerdict(None)
    assert fail_open_manager.request_timestamps


def test_generic_redis_error_raises_when_fail_open_is_false(
    manager: RateLimitManager,
) -> None:
    conn = MagicMock()
    conn.evalsha = MagicMock(side_effect=RedisError("connection refused"))
    manager.redis_handler = _make_redis_handler(conn)

    with pytest.raises(GuardRedisError):
        _verdict(manager)


def test_generic_redis_error_falls_back_when_fail_open_is_true(
    fail_open_manager: RateLimitManager,
) -> None:
    conn = MagicMock()
    conn.evalsha = MagicMock(side_effect=RedisError("connection refused"))
    fail_open_manager.redis_handler = _make_redis_handler(conn)

    result = _verdict(fail_open_manager)

    assert result == RateLimitVerdict(None)
    assert fail_open_manager.request_timestamps


def test_fail_open_warning_logged_once_across_many_calls(
    fail_open_manager: RateLimitManager, caplog: pytest.LogCaptureFixture
) -> None:
    import logging

    conn = MagicMock()
    conn.evalsha = MagicMock(side_effect=RedisError("connection refused"))
    fail_open_manager.redis_handler = _make_redis_handler(conn)

    caplog.set_level(logging.WARNING)
    for _ in range(5):
        result = _verdict(fail_open_manager)
        assert result == RateLimitVerdict(None)
    assert fail_open_manager.request_timestamps

    warnings = [
        r for r in caplog.records if "Redis unavailable for rate limiting" in r.message
    ]
    assert len(warnings) == 1
    assert conn.script_load.call_count == 0


def test_script_reloaded_emits_agent_event(
    manager: RateLimitManager,
) -> None:
    conn = MagicMock()
    conn.evalsha = MagicMock(side_effect=[NoScriptError("NOSCRIPT"), [0, 0, 0]])
    conn.script_load = MagicMock(return_value="newsha")
    manager.redis_handler = _make_redis_handler(conn)

    agent = MagicMock()
    manager.agent_handler = agent

    _verdict(manager)

    assert agent.send_event.call_count == 1
    sent_event = agent.send_event.call_args.args[0]
    assert sent_event.event_type == "rate_limit_script_reloaded"
    assert sent_event.handler_name == "rate_limit"


def test_script_reloaded_without_agent_handler_no_error(
    manager: RateLimitManager,
) -> None:
    conn = MagicMock()
    conn.evalsha = MagicMock(side_effect=[NoScriptError("NOSCRIPT"), [0, 0, 0]])
    conn.script_load = MagicMock(return_value="newsha")
    manager.redis_handler = _make_redis_handler(conn)
    manager.agent_handler = None

    result = _verdict(manager)

    assert result == RateLimitVerdict(None)


def test_script_reload_event_emission_failure_swallowed(
    manager: RateLimitManager, caplog: pytest.LogCaptureFixture
) -> None:
    import logging

    conn = MagicMock()
    conn.evalsha = MagicMock(side_effect=[NoScriptError("NOSCRIPT"), [0, 0, 0]])
    conn.script_load = MagicMock(return_value="newsha")
    manager.redis_handler = _make_redis_handler(conn)

    agent = MagicMock()
    agent.send_event = MagicMock(side_effect=RuntimeError("agent down"))
    manager.agent_handler = agent

    caplog.set_level(logging.ERROR)
    result = _verdict(manager)

    assert result == RateLimitVerdict(None)
    assert any(
        "Failed to send script-reload event" in r.message for r in caplog.records
    )
