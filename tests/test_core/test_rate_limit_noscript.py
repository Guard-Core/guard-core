from unittest.mock import AsyncMock, MagicMock

import pytest
from redis.exceptions import NoScriptError, RedisError

from guard_core.exceptions import GuardRedisError
from guard_core.handlers import ratelimit_handler
from guard_core.handlers.ratelimit_handler import (
    RateLimitManager,
    RateLimitTier,
    RateLimitVerdict,
)
from guard_core.models import SecurityConfig


@pytest.fixture(autouse=True)
def _reset_redis_fail_open_warning() -> None:
    ratelimit_handler._redis_fail_open_warned = False


@pytest.fixture
def manager() -> RateLimitManager:
    config = SecurityConfig(enable_redis=True, rate_limit=100, rate_limit_window=60)
    mgr = RateLimitManager(config)
    mgr.rate_limit_script_sha = "deadbeef"
    return mgr


@pytest.fixture
def fail_open_manager() -> RateLimitManager:
    config = SecurityConfig(
        enable_redis=True,
        rate_limit=100,
        rate_limit_window=60,
        redis_fail_open=True,
    )
    mgr = RateLimitManager(config)
    mgr.rate_limit_script_sha = "deadbeef"
    return mgr


async def _verdict(manager: RateLimitManager) -> RateLimitVerdict:
    tiers = [RateLimitTier("global", 100, 60)]
    return await manager._tier_verdict("1.1.1.1", tiers, manager.config)


def _make_redis_handler(conn: AsyncMock) -> MagicMock:
    redis_handler = MagicMock()
    redis_handler.config = MagicMock(redis_prefix="test:")
    cm = AsyncMock()
    cm.__aenter__ = AsyncMock(return_value=conn)
    cm.__aexit__ = AsyncMock(return_value=None)
    redis_handler.get_connection = MagicMock(return_value=cm)
    return redis_handler


@pytest.mark.asyncio
async def test_noscript_triggers_reload_and_retry_succeeds(
    manager: RateLimitManager,
) -> None:
    conn = AsyncMock()
    conn.evalsha = AsyncMock(side_effect=[NoScriptError("NOSCRIPT"), [0, 0, 0]])
    conn.script_load = AsyncMock(return_value="newsha")
    manager.redis_handler = _make_redis_handler(conn)

    result = await _verdict(manager)

    assert result == RateLimitVerdict(None)
    assert conn.script_load.await_count == 1
    assert conn.evalsha.await_count == 2
    assert manager.rate_limit_script_sha == "newsha"


@pytest.mark.asyncio
async def test_noscript_reload_failure_raises_when_fail_open_is_false(
    manager: RateLimitManager, caplog: pytest.LogCaptureFixture
) -> None:
    import logging

    conn = AsyncMock()
    conn.evalsha = AsyncMock(side_effect=NoScriptError("NOSCRIPT"))
    conn.script_load = AsyncMock(side_effect=RedisError("connection lost"))
    manager.redis_handler = _make_redis_handler(conn)

    caplog.set_level(logging.ERROR)
    with pytest.raises(GuardRedisError):
        await _verdict(manager)

    assert any("Redis rate limiting error" in r.message for r in caplog.records)


@pytest.mark.asyncio
async def test_noscript_reload_failure_falls_back_when_fail_open_is_true(
    fail_open_manager: RateLimitManager, caplog: pytest.LogCaptureFixture
) -> None:
    import logging

    conn = AsyncMock()
    conn.evalsha = AsyncMock(side_effect=NoScriptError("NOSCRIPT"))
    conn.script_load = AsyncMock(side_effect=RedisError("connection lost"))
    fail_open_manager.redis_handler = _make_redis_handler(conn)

    caplog.set_level(logging.WARNING)
    result = await _verdict(fail_open_manager)

    assert result == RateLimitVerdict(None)
    assert fail_open_manager.request_timestamps
    assert any(
        "Redis unavailable for rate limiting" in r.message for r in caplog.records
    )


@pytest.mark.asyncio
async def test_double_noscript_raises_when_fail_open_is_false(
    manager: RateLimitManager,
) -> None:
    conn = AsyncMock()
    conn.evalsha = AsyncMock(
        side_effect=[NoScriptError("first"), NoScriptError("second")]
    )
    conn.script_load = AsyncMock(return_value="newsha")
    manager.redis_handler = _make_redis_handler(conn)

    with pytest.raises(GuardRedisError):
        await _verdict(manager)


@pytest.mark.asyncio
async def test_double_noscript_falls_back_when_fail_open_is_true(
    fail_open_manager: RateLimitManager,
) -> None:
    conn = AsyncMock()
    conn.evalsha = AsyncMock(
        side_effect=[NoScriptError("first"), NoScriptError("second")]
    )
    conn.script_load = AsyncMock(return_value="newsha")
    fail_open_manager.redis_handler = _make_redis_handler(conn)

    result = await _verdict(fail_open_manager)

    assert result == RateLimitVerdict(None)
    assert fail_open_manager.request_timestamps


@pytest.mark.asyncio
async def test_generic_redis_error_raises_when_fail_open_is_false(
    manager: RateLimitManager,
) -> None:
    conn = AsyncMock()
    conn.evalsha = AsyncMock(side_effect=RedisError("connection refused"))
    manager.redis_handler = _make_redis_handler(conn)

    with pytest.raises(GuardRedisError):
        await _verdict(manager)


@pytest.mark.asyncio
async def test_generic_redis_error_falls_back_when_fail_open_is_true(
    fail_open_manager: RateLimitManager,
) -> None:
    conn = AsyncMock()
    conn.evalsha = AsyncMock(side_effect=RedisError("connection refused"))
    fail_open_manager.redis_handler = _make_redis_handler(conn)

    result = await _verdict(fail_open_manager)

    assert result == RateLimitVerdict(None)
    assert fail_open_manager.request_timestamps


@pytest.mark.asyncio
async def test_fail_open_warning_logged_once_across_many_calls(
    fail_open_manager: RateLimitManager, caplog: pytest.LogCaptureFixture
) -> None:
    import logging

    conn = AsyncMock()
    conn.evalsha = AsyncMock(side_effect=RedisError("connection refused"))
    fail_open_manager.redis_handler = _make_redis_handler(conn)

    caplog.set_level(logging.WARNING)
    for _ in range(5):
        result = await _verdict(fail_open_manager)
        assert result == RateLimitVerdict(None)
    assert fail_open_manager.request_timestamps

    warnings = [
        r for r in caplog.records if "Redis unavailable for rate limiting" in r.message
    ]
    assert len(warnings) == 1
    assert conn.script_load.await_count == 0


@pytest.mark.asyncio
async def test_script_reloaded_emits_agent_event(
    manager: RateLimitManager,
) -> None:
    conn = AsyncMock()
    conn.evalsha = AsyncMock(side_effect=[NoScriptError("NOSCRIPT"), [0, 0, 0]])
    conn.script_load = AsyncMock(return_value="newsha")
    manager.redis_handler = _make_redis_handler(conn)

    agent = AsyncMock()
    manager.agent_handler = agent

    await _verdict(manager)

    assert agent.send_event.await_count == 1
    sent_event = agent.send_event.await_args.args[0]
    assert sent_event.event_type == "rate_limit_script_reloaded"
    assert sent_event.handler_name == "rate_limit"


@pytest.mark.asyncio
async def test_script_reloaded_without_agent_handler_no_error(
    manager: RateLimitManager,
) -> None:
    conn = AsyncMock()
    conn.evalsha = AsyncMock(side_effect=[NoScriptError("NOSCRIPT"), [0, 0, 0]])
    conn.script_load = AsyncMock(return_value="newsha")
    manager.redis_handler = _make_redis_handler(conn)
    manager.agent_handler = None

    result = await _verdict(manager)

    assert result == RateLimitVerdict(None)


@pytest.mark.asyncio
async def test_script_reload_event_emission_failure_swallowed(
    manager: RateLimitManager, caplog: pytest.LogCaptureFixture
) -> None:
    import logging

    conn = AsyncMock()
    conn.evalsha = AsyncMock(side_effect=[NoScriptError("NOSCRIPT"), [0, 0, 0]])
    conn.script_load = AsyncMock(return_value="newsha")
    manager.redis_handler = _make_redis_handler(conn)

    agent = AsyncMock()
    agent.send_event = AsyncMock(side_effect=RuntimeError("agent down"))
    manager.agent_handler = agent

    caplog.set_level(logging.ERROR)
    result = await _verdict(manager)

    assert result == RateLimitVerdict(None)
    assert any(
        "Failed to send script-reload event" in r.message for r in caplog.records
    )
