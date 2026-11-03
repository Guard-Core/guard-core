import logging
from typing import Any
from unittest.mock import MagicMock

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.core.checks.implementations.rate_limit import RateLimitCheck
from tests.test_sync.conftest import SyncMockGuardRequest


def test_a_ban_with_shared_counts_but_no_redis_handler_forgets_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SyncSecurityConfig(enable_redis=False, enable_rate_limit_auto_ban=True)
    middleware = MagicMock()
    middleware.config = config
    middleware.logger = logging.getLogger("test_rate_limit_autoban_without_redis")
    middleware.suspicious_request_counts = {}
    check = RateLimitCheck(middleware)
    forgotten: list[Any] = []

    def forget(handler: object, identity: str) -> None:
        forgotten.append(handler)

    monkeypatch.setattr(check, "_shared_violation_counts", MagicMock(return_value={}))
    monkeypatch.setattr(
        "guard_core.sync.core.checks.implementations.rate_limit._try_threshold_ban",
        MagicMock(return_value=True),
    )
    monkeypatch.setattr(
        "guard_core.sync.core.checks.implementations.rate_limit.forget_shared_violations",
        forget,
    )
    request = SyncMockGuardRequest(path="/x", client_host="203.0.113.77")
    request.state.client_ip = "203.0.113.77"
    request.state.route_config = None
    request.state.is_whitelisted = False

    check._record_rate_limit_autoban(request, "203.0.113.77", "trigger")

    assert forgotten == []
