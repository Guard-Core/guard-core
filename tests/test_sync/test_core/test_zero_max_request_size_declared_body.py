from unittest.mock import MagicMock

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.core.checks.implementations.request_size_content import (
    RequestSizeContentCheck,
)
from guard_core.sync.decorators.base import RouteConfig
from tests.test_sync.conftest import MockGuardResponse, SyncMockGuardRequest


@pytest.mark.parametrize(
    "headers",
    [{"content-length": "1"}, {"content-length": "1048576"}],
    ids=["one-byte", "one-mebibyte"],
)
def test_zero_max_request_size_refuses_a_declared_body_without_reading_it(
    headers: dict[str, str],
) -> None:
    mw = MagicMock()
    mw.config = SyncSecurityConfig(enable_redis=False)
    mw.event_bus = MagicMock()
    mw.event_bus.send_middleware_event = MagicMock()
    mw.create_error_response = MagicMock(
        side_effect=lambda status_code, default_message: MockGuardResponse(
            default_message, status_code
        )
    )
    request = SyncMockGuardRequest(method="POST", headers=headers)
    route = RouteConfig()
    route.max_request_size = 0
    request.state.route_config = route
    response = RequestSizeContentCheck(mw).check(request)
    assert response is not None
    assert response.status_code == 413
