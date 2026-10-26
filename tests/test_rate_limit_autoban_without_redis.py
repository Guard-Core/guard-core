import logging
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from guard_core.core.checks.implementations.rate_limit import RateLimitCheck
from guard_core.models import SecurityConfig
from tests.conftest import MockGuardRequest


async def test_a_ban_with_shared_counts_but_no_redis_handler_forgets_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SecurityConfig(enable_redis=False, enable_rate_limit_auto_ban=True)
    middleware = MagicMock()
    middleware.config = config
    middleware.logger = logging.getLogger("test_rate_limit_autoban_without_redis")
    middleware.suspicious_request_counts = {}
    check = RateLimitCheck(middleware)
    forgotten: list[Any] = []

    async def forget(handler: Any, identity: str) -> None:
        forgotten.append(handler)

    monkeypatch.setattr(check, "_shared_violation_counts", AsyncMock(return_value={}))
    monkeypatch.setattr(
        "guard_core.core.checks.implementations.rate_limit._try_threshold_ban",
        AsyncMock(return_value=True),
    )
    monkeypatch.setattr(
        "guard_core.core.checks.implementations.rate_limit.forget_shared_violations",
        forget,
    )
    request = MockGuardRequest(path="/x", client_host="203.0.113.77")
    request.state.client_ip = "203.0.113.77"
    request.state.route_config = None
    request.state.is_whitelisted = False

    await check._record_rate_limit_autoban(request, "203.0.113.77", "trigger")

    assert forgotten == []
