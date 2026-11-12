import logging
from unittest.mock import AsyncMock, MagicMock

import pytest

from guard_core.core.checks.implementations.suspicious_activity import (
    SuspiciousActivityCheck,
)
from guard_core.models import SecurityConfig
from tests.conftest import MockGuardRequest

PROBE = "/wp-login.php"


def _check(template: str | None) -> SuspiciousActivityCheck:
    middleware = MagicMock()
    middleware.config = SecurityConfig(
        enable_redis=False, enable_penetration_detection=True
    )
    middleware.logger = logging.getLogger("test_decoy_route_gate")
    middleware.suspicious_request_counts = {}
    middleware.event_bus.send_middleware_event = AsyncMock()
    middleware.create_error_response = AsyncMock(
        side_effect=lambda status_code, default_message: MagicMock(
            status_code=status_code
        )
    )
    middleware.route_resolver.should_bypass_check = lambda *_: False
    middleware.route_template = MagicMock(return_value=template)
    return SuspiciousActivityCheck(middleware)


async def _status(template: str | None) -> int | None:
    request = MockGuardRequest(path=PROBE)
    request.state.client_ip = "203.0.113.31"
    request.state.route_config = None
    response = await _check(template).check(request)
    return None if response is None else response.status_code


async def test_a_decoy_registered_as_a_literal_route_is_clean() -> None:
    assert await _status(PROBE) is None


async def test_a_probe_the_app_does_not_declare_is_flagged() -> None:
    assert await _status(None) == 400


@pytest.mark.parametrize("template", ["/{page:path}", "/<path:filename>", "/{page}"])
async def test_a_catch_all_or_converter_route_does_not_declare_the_probe(
    template: str,
) -> None:
    assert await _status(template) == 400
