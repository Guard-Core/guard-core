import asyncio
import time
import uuid
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from redis.asyncio import Redis
from redis.exceptions import ConnectionError

from guard_core.exceptions import GuardRedisError
from guard_core.handlers.redis_handler import redis_handler
from guard_core.models import SecurityConfig


@pytest.mark.asyncio
async def test_redis_basic_operations(security_config_redis: SecurityConfig) -> None:
    handler = redis_handler(security_config_redis)
    await handler.initialize()

    await handler.set_key("test", "key1", "value1")
    value = await handler.get_key("test", "key1")
    assert value == "value1"

    exists = await handler.exists("test", "key1")
    assert exists is True

    await handler.delete("test", "key1")
    exists = await handler.exists("test", "key1")
    assert exists is False

    await handler.close()


@pytest.mark.asyncio
async def test_redis_disabled(security_config: SecurityConfig) -> None:
    handler = redis_handler(security_config)
    await handler.initialize()

    assert not security_config.enable_redis
    assert handler._redis is None
    result = await handler.set_key("test", "key1", "value1")
    assert result is None
    value = await handler.get_key("test", "key1")
    assert value is None


@pytest.mark.asyncio
async def test_redis_error_handling(security_config_redis: SecurityConfig) -> None:
    handler = redis_handler(security_config_redis)
    await handler.initialize()

    async def _fail_operation(conn: Any) -> None:
        raise ConnectionError("Test connection error")

    with pytest.raises(GuardRedisError) as exc_info:
        await handler.safe_operation(_fail_operation)
    assert exc_info.value.status_code == 503

    await handler.close()


@pytest.mark.asyncio
async def test_redis_ttl_operations(security_config_redis: SecurityConfig) -> None:
    handler = redis_handler(security_config_redis)
    await handler.initialize()

    await handler.set_key("test", "ttl_key", "value", ttl=1)
    value = await handler.get_key("test", "ttl_key")
    assert value == "value"

    await asyncio.sleep(1.1)
    value = await handler.get_key("test", "ttl_key")
    assert value is None

    await handler.close()


@pytest.mark.asyncio
async def test_redis_increment_operations(
    security_config_redis: SecurityConfig,
) -> None:
    handler = redis_handler(security_config_redis)
    await handler.initialize()

    async with handler.get_connection() as conn:
        prefix = security_config_redis.redis_prefix
        await conn.delete(f"{prefix}test:counter")
        await conn.delete(f"{prefix}test:ttl_counter")

    value = await handler.incr("test", "counter")
    assert value == 1
    value = await handler.incr("test", "counter")
    assert value == 2

    value = await handler.incr("test", "ttl_counter", ttl=1)
    assert value == 1
    await asyncio.sleep(1.1)
    exists = await handler.exists("test", "ttl_counter")
    assert not exists

    await handler.close()


@pytest.mark.asyncio
async def test_record_sliding_window_hit_accumulates_and_trips(
    security_config_redis: SecurityConfig,
) -> None:
    handler = redis_handler(security_config_redis)
    await handler.initialize()

    async with handler.get_connection() as conn:
        prefix = security_config_redis.redis_prefix
        await conn.delete(f"{prefix}sliding_window_test:accumulate")

    base = 2_000_000_000.0
    window_start = base - 60

    count = await handler.record_sliding_window_hit(
        "sliding_window_test", "accumulate", base, window_start, 60
    )
    assert count == 1

    count = await handler.record_sliding_window_hit(
        "sliding_window_test", "accumulate", base + 1, window_start, 60
    )
    assert count == 2

    count = await handler.record_sliding_window_hit(
        "sliding_window_test", "accumulate", base + 2, window_start, 60
    )
    assert count == 3

    await handler.close()


@pytest.mark.asyncio
async def test_record_sliding_window_hit_identical_timestamps_each_count_separately(
    security_config_redis: SecurityConfig,
) -> None:
    handler = redis_handler(security_config_redis)
    await handler.initialize()

    key = f"frozen_clock_{uuid.uuid4().hex}"
    async with handler.get_connection() as conn:
        prefix = security_config_redis.redis_prefix
        await conn.delete(f"{prefix}sliding_window_test:{key}")

    frozen_timestamp = 2_000_000_500.0
    window_start = frozen_timestamp - 60

    count = 0
    for _ in range(50):
        count = await handler.record_sliding_window_hit(
            "sliding_window_test",
            key,
            frozen_timestamp,
            window_start,
            60,
        )
    assert count == 50

    await handler.close()


@pytest.mark.asyncio
async def test_record_sliding_window_hit_prunes_entries_before_window_start(
    security_config_redis: SecurityConfig,
) -> None:
    handler = redis_handler(security_config_redis)
    await handler.initialize()

    async with handler.get_connection() as conn:
        prefix = security_config_redis.redis_prefix
        await conn.delete(f"{prefix}sliding_window_test:prune")

    base = 2_000_000_100.0

    await handler.record_sliding_window_hit(
        "sliding_window_test", "prune", base - 200, base - 260, 60
    )
    count = await handler.record_sliding_window_hit(
        "sliding_window_test", "prune", base, base - 60, 60
    )
    assert count == 1

    await handler.close()


@pytest.mark.asyncio
async def test_record_sliding_window_hit_window_start_boundary_is_inclusive(
    security_config_redis: SecurityConfig,
) -> None:
    handler = redis_handler(security_config_redis)
    await handler.initialize()

    async with handler.get_connection() as conn:
        prefix = security_config_redis.redis_prefix
        await conn.delete(f"{prefix}sliding_window_test:boundary_at")
        await conn.delete(f"{prefix}sliding_window_test:boundary_before")

    window_start = 2_000_000_200.0

    at_boundary_count = await handler.record_sliding_window_hit(
        "sliding_window_test", "boundary_at", window_start, window_start, 60
    )
    assert at_boundary_count == 1

    before_boundary_count = await handler.record_sliding_window_hit(
        "sliding_window_test",
        "boundary_before",
        window_start - 0.001,
        window_start,
        60,
    )
    assert before_boundary_count == 0

    await handler.close()


@pytest.mark.asyncio
async def test_record_sliding_window_hit_key_expires_with_ttl(
    security_config_redis: SecurityConfig,
) -> None:
    handler = redis_handler(security_config_redis)
    await handler.initialize()

    async with handler.get_connection() as conn:
        prefix = security_config_redis.redis_prefix
        await conn.delete(f"{prefix}sliding_window_test:expiry")

    now = time.time()
    count = await handler.record_sliding_window_hit(
        "sliding_window_test", "expiry", now, now - 1, 1
    )
    assert count == 1

    await asyncio.sleep(1.2)
    exists = await handler.exists("sliding_window_test", "expiry")
    assert not exists

    await handler.close()


@pytest.mark.asyncio
async def test_record_sliding_window_hit_disabled_redis_returns_zero(
    security_config: SecurityConfig,
) -> None:
    handler = redis_handler(security_config)
    await handler.initialize()

    assert not security_config.enable_redis
    count = await handler.record_sliding_window_hit(
        "sliding_window_test", "disabled", 1.0, 0.0, 60
    )
    assert count == 0


@pytest.mark.asyncio
async def test_count_sliding_window_hits_counts_without_recording(
    security_config_redis: SecurityConfig,
) -> None:
    handler = redis_handler(security_config_redis)
    await handler.initialize()
    base = 2_000_000_000.0
    key = "count_only"
    try:
        await handler.record_sliding_window_hit(
            "sliding_window_test", key, base - 100, base - 200, 60
        )
        await handler.record_sliding_window_hit(
            "sliding_window_test", key, base, base - 200, 60
        )
        assert (
            await handler.count_sliding_window_hits(
                "sliding_window_test", key, base - 60
            )
            == 1
        )
        assert (
            await handler.count_sliding_window_hits(
                "sliding_window_test", key, base - 200
            )
            == 2
        )
    finally:
        await handler.delete_pattern("sliding_window_test*")
        await handler.close()


@pytest.mark.asyncio
async def test_count_sliding_window_hits_disabled_redis_returns_zero(
    security_config: SecurityConfig,
) -> None:
    handler = redis_handler(security_config)
    await handler.initialize()

    assert not security_config.enable_redis
    assert await handler.count_sliding_window_hits("sliding_window_test", "x", 0.0) == 0


@pytest.mark.asyncio
async def test_count_sliding_window_hits_returns_zero_when_the_operation_fails(
    security_config_redis: SecurityConfig, monkeypatch: Any
) -> None:
    handler = redis_handler(security_config_redis)
    await handler.initialize()
    monkeypatch.setattr(handler, "safe_operation", AsyncMock(return_value=None))
    try:
        assert (
            await handler.count_sliding_window_hits("sliding_window_test", "x", 0.0)
            == 0
        )
    finally:
        await handler.close()


@pytest.mark.asyncio
async def test_redis_connection_context_get_error(
    security_config_redis: SecurityConfig, monkeypatch: Any
) -> None:
    handler = redis_handler(security_config_redis)
    await handler.initialize()

    async def mock_get(*args: Any, **kwargs: Any) -> None:
        raise ConnectionError("Test connection error on get")

    with pytest.raises(GuardRedisError) as exc_info:
        async with handler.get_connection() as conn:
            monkeypatch.setattr(conn, "get", mock_get)
            await conn.get("test:key")

    assert exc_info.value.status_code == 503

    await handler.close()


@pytest.mark.asyncio
async def test_redis_connection_failures(security_config_redis: SecurityConfig) -> None:
    bad_config = SecurityConfig(
        **{
            **security_config_redis.model_dump(
                exclude={"ipinfo_token", "ipinfo_db_path"}
            ),
            "redis_url": "redis://nonexistent:6379",
        }
    )
    handler = redis_handler(bad_config)
    with pytest.raises(GuardRedisError) as exc_info:
        await handler.initialize()
    assert exc_info.value.status_code == 503
    assert handler._redis is None

    handler = redis_handler(security_config_redis)
    await handler.initialize()

    await handler.close()
    with pytest.raises(GuardRedisError) as exc_info:
        await handler.get_key("test", "key")
    assert exc_info.value.status_code == 503

    handler._redis = None
    with pytest.raises(GuardRedisError) as exc_info:
        await handler.safe_operation(lambda conn: conn.get("test:key"))
    assert exc_info.value.status_code == 503


@pytest.mark.asyncio
async def test_redis_disabled_operations(security_config_redis: SecurityConfig) -> None:
    security_config_redis.enable_redis = False
    handler = redis_handler(security_config_redis)

    assert await handler.get_key("test", "key") is None
    assert await handler.set_key("test", "key", "value") is None
    assert await handler.incr("test", "counter") is None
    assert await handler.exists("test", "key") is None
    assert await handler.delete("test", "key") is None


@pytest.mark.asyncio
async def test_redis_failed_initialization_operations(
    security_config_redis: SecurityConfig,
) -> None:
    bad_config = SecurityConfig(
        **{
            **security_config_redis.model_dump(
                exclude={"ipinfo_token", "ipinfo_db_path"}
            ),
            "redis_url": "redis://invalid:6379",
        }
    )
    handler = redis_handler(bad_config)

    with pytest.raises(GuardRedisError) as exc_info:
        await handler.get_key("test", "key")
    assert exc_info.value.status_code == 503

    with pytest.raises(GuardRedisError) as exc_info:
        await handler.set_key("test", "key", "value")
    assert exc_info.value.status_code == 503


@pytest.mark.asyncio
async def test_redis_url_none(security_config_redis: SecurityConfig) -> None:
    security_config_redis.redis_url = None

    handler = redis_handler(security_config_redis)

    with patch("logging.Logger.warning") as mock_warning:
        await handler.initialize()
        mock_warning.assert_called_once_with("Redis URL is None, skipping connection")
        assert handler._redis is None


@pytest.mark.asyncio
async def test_safe_operation_redis_disabled(security_config: SecurityConfig) -> None:
    handler = redis_handler(security_config)

    mock_func = AsyncMock()
    result = await handler.safe_operation(mock_func)

    assert result is None
    mock_func.assert_not_called()


@pytest.mark.asyncio
async def test_connection_context_redis_none(
    security_config_redis: SecurityConfig, monkeypatch: Any
) -> None:
    handler = redis_handler(security_config_redis)

    initialize_called = False

    async def mocked_initialize() -> None:
        nonlocal initialize_called
        initialize_called = True

    monkeypatch.setattr(handler, "initialize", mocked_initialize)

    handler._closed = False
    handler._redis = None

    with pytest.raises(GuardRedisError) as exc_info:
        await handler.get_connection().__aenter__()

    assert initialize_called, "initialize() was not called"
    assert exc_info.value.status_code == 503
    assert "Redis connection failed" in exc_info.value.detail


@pytest.mark.asyncio
async def test_redis_keys_and_delete_pattern_with_redis_disabled() -> None:
    config = SecurityConfig(enable_redis=False)
    handler = redis_handler(config)

    keys_result = await handler.keys("*")
    assert keys_result is None

    delete_result = await handler.delete_pattern("*")
    assert delete_result is None


async def test_initialize_logs_warning_when_redis_url_is_none() -> None:
    from unittest.mock import patch

    from guard_core.handlers.redis_handler import RedisManager
    from guard_core.models import SecurityConfig

    RedisManager._instance = None
    config = SecurityConfig(enable_redis=True, redis_url=None)
    manager = RedisManager(config)
    with patch.object(manager.logger, "warning") as mock_warn:
        await manager.initialize()
    mock_warn.assert_called()
    RedisManager._instance = None


async def test_close_noop_when_redis_not_connected() -> None:
    from guard_core.handlers.redis_handler import RedisManager
    from guard_core.models import SecurityConfig

    RedisManager._instance = None
    manager = RedisManager(SecurityConfig(enable_redis=True))
    manager._redis = None
    await manager.close()
    assert manager._closed is True
    RedisManager._instance = None


async def test_initialize_when_from_url_returns_none_skips_ping() -> None:
    from unittest.mock import patch

    from guard_core.handlers.redis_handler import RedisManager
    from guard_core.models import SecurityConfig

    RedisManager._instance = None
    config = SecurityConfig(enable_redis=True, redis_url="redis://localhost:6379")
    manager = RedisManager(config)
    with patch("guard_core.handlers.redis_handler.Redis.from_url", return_value=None):
        await manager.initialize()
    assert manager._redis is None
    RedisManager._instance = None


async def test_initialize_twice_closes_previous_client_exactly_once() -> None:
    from guard_core.handlers.redis_handler import RedisManager
    from guard_core.models import SecurityConfig

    RedisManager._instance = None
    config = SecurityConfig(enable_redis=True, redis_url="redis://localhost:6379")
    manager = RedisManager(config)

    first_client = AsyncMock()
    first_client.ping = AsyncMock(return_value=True)
    first_client.aclose = AsyncMock()

    second_client = AsyncMock()
    second_client.ping = AsyncMock(return_value=True)
    second_client.aclose = AsyncMock()

    with patch(
        "guard_core.handlers.redis_handler.Redis.from_url",
        side_effect=[first_client, second_client],
    ):
        await manager.initialize()
        await manager.initialize()

    first_client.aclose.assert_called_once()
    second_client.aclose.assert_not_called()
    assert manager._redis is second_client
    RedisManager._instance = None


async def test_initialize_disabled_redis_closes_existing_client() -> None:
    from guard_core.handlers.redis_handler import RedisManager
    from guard_core.models import SecurityConfig

    RedisManager._instance = None
    config = SecurityConfig(enable_redis=True, redis_url="redis://localhost:6379")
    manager = RedisManager(config)

    existing_client = AsyncMock()
    existing_client.aclose = AsyncMock()
    redis_or_none: Redis | None = existing_client
    manager._redis = redis_or_none

    config.enable_redis = False
    await manager.initialize()

    existing_client.aclose.assert_called_once()
    assert manager._redis is None
    RedisManager._instance = None


async def test_initialize_ping_failure_closes_new_client_before_raising() -> None:
    from guard_core.handlers.redis_handler import RedisManager
    from guard_core.models import SecurityConfig

    RedisManager._instance = None
    config = SecurityConfig(enable_redis=True, redis_url="redis://localhost:6379")
    manager = RedisManager(config)

    failing_client = AsyncMock()
    failing_client.ping = AsyncMock(side_effect=ConnectionError("ping failed"))
    failing_client.aclose = AsyncMock()

    with patch(
        "guard_core.handlers.redis_handler.Redis.from_url",
        return_value=failing_client,
    ):
        with pytest.raises(GuardRedisError):
            await manager.initialize()

    failing_client.aclose.assert_called_once()
    assert manager._redis is None
    RedisManager._instance = None


async def test_close_twice_does_not_raise() -> None:
    from guard_core.handlers.redis_handler import RedisManager
    from guard_core.models import SecurityConfig

    RedisManager._instance = None
    config = SecurityConfig(enable_redis=True, redis_url="redis://localhost:6379")
    manager = RedisManager(config)

    client = AsyncMock()
    client.aclose = AsyncMock()
    redis_or_none: Redis | None = client
    manager._redis = redis_or_none

    await manager.close()
    await manager.close()

    client.aclose.assert_called_once()
    assert manager._closed is True
    RedisManager._instance = None


async def test_close_stale_client_failure_is_logged_and_swallowed() -> None:
    from guard_core.handlers.redis_handler import RedisManager
    from guard_core.models import SecurityConfig

    RedisManager._instance = None
    config = SecurityConfig(enable_redis=True, redis_url="redis://localhost:6379")
    manager = RedisManager(config)

    stale_client = AsyncMock()
    stale_client.aclose = AsyncMock(
        side_effect=RuntimeError("Future attached to a different loop")
    )
    redis_or_none: Redis | None = stale_client
    manager._redis = redis_or_none

    with patch.object(manager.logger, "warning") as mock_warning:
        await manager.close()

    stale_client.aclose.assert_called_once()
    mock_warning.assert_called_once()
    assert manager._redis is None
    assert manager._closed is True
    RedisManager._instance = None


async def test_initialize_twice_against_real_redis_does_not_warn(
    security_config_redis: SecurityConfig,
) -> None:
    import gc
    import warnings

    handler = redis_handler(security_config_redis)

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        await handler.initialize()
        await handler.initialize()
        await handler.close()
        gc.collect()

    resource_warnings = [w for w in caught if issubclass(w.category, ResourceWarning)]
    assert resource_warnings == []


@pytest.mark.asyncio
async def test_record_sliding_window_hit_reloads_its_script_after_a_script_flush(
    security_config_redis: SecurityConfig,
) -> None:
    handler = redis_handler(security_config_redis)
    await handler.initialize()
    key = f"script_flush_{uuid.uuid4().hex}"
    async with handler.get_connection() as conn:
        await conn.script_flush()

    count = await handler.record_sliding_window_hit(
        "sliding_window_test", key, 2_000_000_000.0, 1_999_999_000.0, 60
    )

    assert count == 1
    await handler.delete("sliding_window_test", key)
    await handler.close()


_NS = "sliding_window_test"


async def _indexed_hits(
    handler: Any, index: str, max_members: int, hits: dict[str, list[float]]
) -> None:
    for key, timestamps in hits.items():
        for timestamp in timestamps:
            await handler.record_sliding_window_hit(
                _NS, key, timestamp, 0.0, 300, index=(index, max_members)
            )


async def _index_members(handler: Any, index: str) -> set[str]:
    prefix = f"{handler.config.redis_prefix}{_NS}:"
    async with handler.get_connection() as conn:
        members = await conn.smembers(f"{prefix}{index}")
    return {member.removeprefix(prefix) for member in members}


@pytest.mark.asyncio
async def test_record_sliding_window_hit_indexes_the_key_with_its_ttl(
    security_config_redis: SecurityConfig,
) -> None:
    handler = redis_handler(security_config_redis)
    await handler.initialize()
    index, first, second = (f"{name}_{uuid.uuid4().hex}" for name in "ifs")
    try:
        count = await handler.record_sliding_window_hit(
            _NS, first, 2_000_000_000.0, 0.0, 600, index=(index, 10)
        )
        await handler.record_sliding_window_hit(
            _NS, second, 2_000_000_000.0, 0.0, 300, index=(index, 10)
        )
        assert count == 1
        assert await _index_members(handler, index) == {first, second}
        async with handler.get_connection() as conn:
            ttl = await conn.ttl(f"{handler.config.redis_prefix}{_NS}:{index}")
        assert 290 < ttl <= 300
    finally:
        await handler.delete_pattern(f"{_NS}:*")
        await handler.close()


@pytest.mark.asyncio
async def test_sum_indexed_window_hits_counts_hits_from_the_window_start(
    security_config_redis: SecurityConfig,
) -> None:
    handler = redis_handler(security_config_redis)
    await handler.initialize()
    index, first, second = (f"{name}_{uuid.uuid4().hex}" for name in "ifs")
    try:
        await _indexed_hits(
            handler, index, 10, {first: [100.0, 200.0, 250.0], second: [200.0]}
        )
        assert await handler.sum_indexed_window_hits(_NS, index, 200.0) == 3
        assert await handler.sum_indexed_window_hits(_NS, "absent", 0.0) == 0
    finally:
        await handler.delete_pattern(f"{_NS}:*")
        await handler.close()


@pytest.mark.asyncio
async def test_sum_indexed_window_hits_drops_members_whose_key_expired(
    security_config_redis: SecurityConfig,
) -> None:
    handler = redis_handler(security_config_redis)
    await handler.initialize()
    index, first, second = (f"{name}_{uuid.uuid4().hex}" for name in "ifs")
    try:
        await _indexed_hits(handler, index, 10, {first: [100.0], second: [100.0]})
        await handler.delete(_NS, first)
        assert await handler.sum_indexed_window_hits(_NS, index, 0.0) == 1
        assert await _index_members(handler, index) == {second}
    finally:
        await handler.delete_pattern(f"{_NS}:*")
        await handler.close()


@pytest.mark.asyncio
async def test_a_full_index_prunes_expired_keys_then_drops_the_new_key(
    security_config_redis: SecurityConfig,
) -> None:
    handler = redis_handler(security_config_redis)
    await handler.initialize()
    index = f"index_{uuid.uuid4().hex}"
    keys = [f"key{n}_{uuid.uuid4().hex}" for n in range(4)]
    try:
        await _indexed_hits(handler, index, 2, {keys[0]: [1.0], keys[1]: [1.0]})
        await handler.delete(_NS, keys[0])
        await _indexed_hits(handler, index, 2, {keys[2]: [1.0]})
        assert await _index_members(handler, index) == {keys[1], keys[2]}
        await _indexed_hits(handler, index, 2, {keys[3]: [1.0]})
        assert await _index_members(handler, index) == {keys[1], keys[2]}
    finally:
        await handler.delete_pattern(f"{_NS}:*")
        await handler.close()


@pytest.mark.asyncio
async def test_sum_indexed_window_hits_reloads_its_script_after_a_script_flush(
    security_config_redis: SecurityConfig,
) -> None:
    handler = redis_handler(security_config_redis)
    await handler.initialize()
    index, key = f"index_{uuid.uuid4().hex}", f"key_{uuid.uuid4().hex}"
    try:
        await _indexed_hits(handler, index, 10, {key: [5.0]})
        async with handler.get_connection() as conn:
            await conn.script_flush()
        assert await handler.sum_indexed_window_hits(_NS, index, 0.0) == 1
    finally:
        await handler.delete_pattern(f"{_NS}:*")
        await handler.close()


@pytest.mark.asyncio
async def test_sum_indexed_window_hits_is_zero_when_redis_is_disabled() -> None:
    handler = redis_handler(SecurityConfig(enable_redis=False))

    assert await handler.sum_indexed_window_hits("ns", "index", 0.0) == 0


@pytest.mark.asyncio
async def test_sum_indexed_window_hits_is_zero_when_the_operation_fails(
    security_config_redis: SecurityConfig,
) -> None:
    handler = redis_handler(security_config_redis)

    with patch.object(handler, "safe_operation", AsyncMock(return_value=None)):
        assert await handler.sum_indexed_window_hits("ns", "index", 0.0) == 0
