from unittest.mock import AsyncMock, MagicMock

import pytest

from guard_core.core.events.metrics import MetricsCollector
from guard_core.core.responses.context import ResponseContext
from guard_core.core.responses.factory import ErrorResponseFactory
from guard_core.models import SecurityConfig
from tests.conftest import MockGuardRequest, MockGuardResponseFactory


def _make_factory() -> ErrorResponseFactory:
    metrics = MagicMock(spec=MetricsCollector)
    metrics.collect_request_metrics = AsyncMock()
    context = ResponseContext(
        config=SecurityConfig(enable_redis=False),
        logger=MagicMock(),
        metrics_collector=metrics,
        response_factory=MockGuardResponseFactory(),
    )
    return ErrorResponseFactory(context)


@pytest.mark.parametrize("method", ["GET", "HEAD"])
async def test_a_safe_method_gets_the_permanent_redirect(method: str) -> None:
    factory = _make_factory()
    request = MockGuardRequest(scheme="http", path="/test", method=method)

    response = await factory.create_https_redirect(request)

    assert response.status_code == 301


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
async def test_a_method_with_a_body_keeps_its_method_and_body_on_the_redirect(
    method: str,
) -> None:
    factory = _make_factory()
    request = MockGuardRequest(scheme="http", path="/test", method=method)

    response = await factory.create_https_redirect(request)

    assert response.status_code == 308
    assert "Location" in response.headers
