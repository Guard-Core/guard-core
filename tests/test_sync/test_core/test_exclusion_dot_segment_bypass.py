from typing import Any
from unittest.mock import MagicMock, Mock

import pytest

from guard_core.models import SecurityConfig
from guard_core.sync.core.validation.context import ValidationContext
from guard_core.sync.core.validation.validator import RequestValidator
from tests.test_sync.conftest import SyncMockGuardRequest

BYPASS_SHAPES = [
    "/admin/../static/x",
    "/admin/..%2fstatic%2fx",
    "/admin/..%2Fstatic%2Fx",
    "/admin/%2e%2e/health",
    "/admin/%2E%2E/health",
    "/admin/..;x/health",
]

LEGITIMATE_EXCLUDED = ["/static/x", "/static/js/app.js", "/health", "/health/"]


@pytest.fixture
def validator() -> RequestValidator:
    config = SecurityConfig(enable_redis=False, exclude_paths=["/static", "/health"])
    event_bus: Any = Mock()
    event_bus.send_middleware_event = MagicMock()
    return RequestValidator(
        ValidationContext(config=config, logger=Mock(), event_bus=event_bus)
    )


@pytest.mark.parametrize("path", BYPASS_SHAPES)
def test_dot_segment_path_reaching_protected_route_is_never_excluded(
    validator: RequestValidator, path: str
) -> None:
    assert validator.is_path_excluded(SyncMockGuardRequest(path=path)) is False


@pytest.mark.parametrize("path", LEGITIMATE_EXCLUDED)
def test_legitimate_excluded_paths_still_skip(
    validator: RequestValidator, path: str
) -> None:
    assert validator.is_path_excluded(SyncMockGuardRequest(path=path)) is True
