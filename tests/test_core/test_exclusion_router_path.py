from typing import Any
from unittest.mock import AsyncMock, Mock

import pytest

from guard_core.core.validation.context import ValidationContext
from guard_core.core.validation.validator import RequestValidator
from guard_core.models import SecurityConfig
from tests.conftest import MockGuardRequest


@pytest.fixture
def validator() -> RequestValidator:
    config = SecurityConfig(
        enable_redis=False, exclude_paths=["/docs", "/static", "/health"]
    )
    event_bus: Any = Mock()
    event_bus.send_middleware_event = AsyncMock()
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
async def test_engine_never_decodes_or_collapses_the_router_path(
    validator: RequestValidator, path: str
) -> None:
    assert await validator.is_path_excluded(MockGuardRequest(path=path)) is False


@pytest.mark.parametrize(
    "path",
    ["/docs", "/docs/", "/static/js/app.js", "/static/app.js;jsessionid=A", "/health"],
)
async def test_router_path_without_anomaly_is_excluded_as_is(
    validator: RequestValidator, path: str
) -> None:
    assert await validator.is_path_excluded(MockGuardRequest(path=path)) is True
