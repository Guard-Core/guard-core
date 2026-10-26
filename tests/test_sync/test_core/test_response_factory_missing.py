from unittest.mock import MagicMock

import pytest

from guard_core.exceptions import GuardCoreError
from guard_core.models import SyncSecurityConfig
from guard_core.sync.core.events.metrics import MetricsCollector
from guard_core.sync.core.responses.context import ResponseContext
from guard_core.sync.core.responses.factory import ErrorResponseFactory
from tests.test_sync.conftest import SyncMockGuardRequest


def _factory_without_a_response_factory() -> ErrorResponseFactory:
    metrics = MagicMock(spec=MetricsCollector)
    metrics.collect_request_metrics = MagicMock()
    context = ResponseContext(
        config=SyncSecurityConfig(enable_redis=False),
        logger=MagicMock(),
        metrics_collector=metrics,
    )
    assert context.response_factory is None
    return ErrorResponseFactory(context)


def test_an_error_response_without_a_factory_names_the_setting() -> None:
    factory = _factory_without_a_response_factory()
    with pytest.raises(GuardCoreError, match="response_factory is not set"):
        factory.create_error_response(403, "denied")


def test_a_https_redirect_without_a_factory_names_the_setting() -> None:
    factory = _factory_without_a_response_factory()
    request = SyncMockGuardRequest(scheme="http", path="/test", method="GET")
    with pytest.raises(GuardCoreError, match="response_factory is not set"):
        factory.create_https_redirect(request)
