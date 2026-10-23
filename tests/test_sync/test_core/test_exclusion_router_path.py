from typing import Any
from unittest.mock import MagicMock, Mock

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.core.validation.context import ValidationContext
from guard_core.sync.core.validation.validator import RequestValidator
from tests.test_sync.conftest import SyncMockGuardRequest


@pytest.fixture
def validator() -> RequestValidator:
    config = SyncSecurityConfig(
        enable_redis=False, exclude_paths=["/docs", "/static", "/health"]
    )
    event_bus: Any = Mock()
    event_bus.send_middleware_event = MagicMock()
    return RequestValidator(
        ValidationContext(config=config, logger=Mock(), event_bus=event_bus)
    )


@pytest.mark.parametrize(
    "path",
    [
        "/%64ocs",
        "/%2564ocs",
        "//health",
        "//docs",
        "/static//x",
        "/health/.",
        "/health%2f",
        "/health%2F",
        "/health%5c",
        "/health\\",
        "/static/%2e/x",
    ],
)
def test_engine_never_decodes_or_collapses_the_router_path(
    validator: RequestValidator, path: str
) -> None:
    assert validator.is_path_excluded(SyncMockGuardRequest(path=path)) is False


@pytest.mark.parametrize(
    "path",
    ["/docs", "/docs/", "/static/js/app.js", "/static/app.js;jsessionid=A", "/health"],
)
def test_router_path_without_anomaly_is_excluded_as_is(
    validator: RequestValidator, path: str
) -> None:
    assert validator.is_path_excluded(SyncMockGuardRequest(path=path)) is True
