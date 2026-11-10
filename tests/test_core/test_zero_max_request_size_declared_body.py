from unittest.mock import AsyncMock, MagicMock

import pytest

from guard_core.core.checks.implementations.request_size_content import (
    RequestSizeContentCheck,
)
from guard_core.decorators.base import RouteConfig
from guard_core.models import SecurityConfig
from tests.conftest import MockGuardRequest, MockGuardResponse


@pytest.mark.parametrize(
    "headers",
    [{"content-length": "1"}, {"content-length": "1048576"}],
    ids=["one-byte", "one-mebibyte"],
)
async def test_zero_max_request_size_refuses_a_declared_body_without_reading_it(
    headers: dict[str, str],
) -> None:
    mw = MagicMock()
    mw.config = SecurityConfig(enable_redis=False)
    mw.event_bus = MagicMock()
    mw.event_bus.send_middleware_event = AsyncMock()
    mw.create_error_response = AsyncMock(
        side_effect=lambda status_code, default_message: MockGuardResponse(
            default_message, status_code
        )
    )
    request = MockGuardRequest(method="POST", headers=headers)
    route = RouteConfig()
    route.max_request_size = 0
    request.state.route_config = route
    response = await RequestSizeContentCheck(mw).check(request)
    assert response is not None
    assert response.status_code == 413
