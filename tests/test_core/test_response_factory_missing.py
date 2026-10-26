from unittest.mock import AsyncMock, MagicMock

import pytest

from guard_core.core.events.metrics import MetricsCollector
from guard_core.core.responses.context import ResponseContext
from guard_core.core.responses.factory import ErrorResponseFactory
from guard_core.exceptions import GuardCoreError
from guard_core.models import SecurityConfig
from tests.conftest import MockGuardRequest


def _factory_without_a_response_factory() -> ErrorResponseFactory:
    metrics = MagicMock(spec=MetricsCollector)
    metrics.collect_request_metrics = AsyncMock()
    context = ResponseContext(
        config=SecurityConfig(enable_redis=False),
        logger=MagicMock(),
        metrics_collector=metrics,
    )
    assert context.response_factory is None
    return ErrorResponseFactory(context)


async def test_an_error_response_without_a_factory_names_the_setting() -> None:
    factory = _factory_without_a_response_factory()
    with pytest.raises(GuardCoreError, match="response_factory is not set"):
        await factory.create_error_response(403, "denied")


async def test_a_https_redirect_without_a_factory_names_the_setting() -> None:
    factory = _factory_without_a_response_factory()
    request = MockGuardRequest(scheme="http", path="/test", method="GET")
    with pytest.raises(GuardCoreError, match="response_factory is not set"):
        await factory.create_https_redirect(request)
