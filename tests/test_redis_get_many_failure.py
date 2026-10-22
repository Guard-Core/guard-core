from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from guard_core.exceptions import GuardRedisError
from guard_core.handlers.redis_handler import RedisManager
from guard_core.models import SecurityConfig


async def test_a_failing_get_many_keeps_the_error_and_the_event() -> None:
    manager = RedisManager(SecurityConfig(redis_prefix="getmany:"))
    client = MagicMock()
    client.execute_command = AsyncMock(side_effect=ValueError("mget exploded"))
    manager._redis = client

    with patch.object(
        RedisManager, "_send_redis_event", new_callable=AsyncMock
    ) as sent:
        with pytest.raises(GuardRedisError) as exc_info:
            await manager.get_many([("banned_ips", "198.51.100.1")])

    assert exc_info.value.status_code == 503
    assert exc_info.value.detail == "Redis operation failed"
    sent.assert_awaited_once()
    assert sent.await_args is not None
    event = sent.await_args.kwargs
    assert event["action_taken"] == "safe_operation_failed"
    assert event["error_type"] == "safe_operation_error"
    assert event["function_name"] == "_get_many"
    assert "mget exploded" in event["reason"]
