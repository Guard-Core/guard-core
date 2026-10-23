from unittest.mock import MagicMock, patch

import pytest

from guard_core.exceptions import GuardRedisError
from guard_core.models import SyncSecurityConfig
from guard_core.sync.handlers.redis_handler import RedisManager


def test_a_failing_get_many_keeps_the_error_and_the_event() -> None:
    manager = RedisManager(SyncSecurityConfig(redis_prefix="getmany:"))
    client = MagicMock()
    client.execute_command = MagicMock(side_effect=ValueError("mget exploded"))
    manager._redis = client

    with patch.object(RedisManager, "_send_redis_event") as sent:
        with pytest.raises(GuardRedisError) as exc_info:
            manager.get_many([("banned_ips", "198.51.100.1")])

    assert exc_info.value.status_code == 503
    assert exc_info.value.detail == "Redis operation failed"
    sent.assert_called_once()
    assert sent.call_args is not None
    event = sent.call_args.kwargs
    assert event["action_taken"] == "safe_operation_failed"
    assert event["error_type"] == "safe_operation_error"
    assert event["function_name"] == "_get_many"
    assert "mget exploded" in event["reason"]
